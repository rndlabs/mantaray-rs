use const_format::concatcp;
use rand::RngCore;

use crate::{
    node::{Fork, Node},
    NODE_FORK_HEADER_SIZE, NODE_FORK_METADATA_BYTES_SIZE, NODE_FORK_PRE_REFERENCE_SIZE,
    NODE_FORK_TYPE_BYTES_SIZE, NODE_HEADER_SIZE, NODE_OBFUSCATION_KEY_SIZE, NODE_PREFIX_MAX_SIZE,
    NT_WITH_METADATA, VERSION_HASH_SIZE,
};

const VERSION_NAME: &str = "mantaray";
const VERSION_CODE_01: &str = "0.1";
const VERSION_CODE_02: &str = "0.2";
const VERSION_SEPARATOR: &str = ":";
// "mantaray:0.1"
#[allow(dead_code)]
const VERSION_STRING_01: &str = concatcp!(VERSION_NAME, VERSION_SEPARATOR, VERSION_CODE_01);
// pre-calculated version string, Keccak-256
const VERSION_HASH_01: &str = "025184789d63635766d78c41900196b57d7400875ebe4d9b5d1e76bd9652a9b7";
// "mantaray:0.2"
#[allow(dead_code)]
const VERSION_STRING_02: &str = concatcp!(VERSION_NAME, VERSION_SEPARATOR, VERSION_CODE_02);
// pre-calculated version string, Keccak-256
const VERSION_HASH_02: &str = "5768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f7b";

pub trait Marshal {
    type Item;

    fn marshal_binary(&self) -> Result<Vec<u8>, String>;
    fn unmarshal_binary(&mut self, data: &mut [u8]) -> Result<(), String>;
}

pub trait MarshalV2 {
    type Item;

    fn unmarshal_binary_02(
        &mut self,
        data: &mut [u8],
        ref_bytes_size: usize,
        metadata_bytes_size: usize,
    ) -> Result<(), String>;
}

impl Marshal for Node {
    type Item = Node;

    fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        // header of bytes at length NFS_HEADER
        let mut header: Vec<u8> = vec![0; NODE_HEADER_SIZE];

        // generate an obfuscation key if not provided
        let obfuscation_key = if self.obfuscation_key.is_empty() {
            let mut rng = rand::thread_rng();
            let mut key = [0u8; NODE_OBFUSCATION_KEY_SIZE];
            rng.fill_bytes(&mut key);
            key.to_vec()
        } else {
            self.obfuscation_key.clone()
        };

        // copy the obfuscation key to the header
        header[..NODE_OBFUSCATION_KEY_SIZE].copy_from_slice(&obfuscation_key);

        // copy the version hash to the header
        header[NODE_OBFUSCATION_KEY_SIZE..NODE_OBFUSCATION_KEY_SIZE + VERSION_HASH_SIZE]
            .copy_from_slice(&hex::decode(&VERSION_HASH_02).unwrap()[..VERSION_HASH_SIZE]);

        // set the ref_bytes_size in the header
        header[NODE_OBFUSCATION_KEY_SIZE + VERSION_HASH_SIZE] =
            self.ref_bytes_size.try_into().unwrap();

        // define an empty vector to store the marshaled data
        let mut data = header;

        // append the node entry to the data vector
        if self.entry.is_empty() {
            // add a 32 byte empty entry to the data vector
            data.extend_from_slice(&[0; 32]);
        } else {
            // copy the entry to the data vector
            data.extend_from_slice(&self.entry);
        }

        // index

        // create an bitfield to store the index
        let mut index = BitField::new();

        // iterate over the forks and set the index bitfield
        for fork in &self.forks {
            index.set(*fork.0);
        }

        // append the index to the data vector
        data.extend_from_slice(index.to_bytes());

        // iterate over the forks set in the indices and append the fork to the data vector
        let mut forks = self.forks.keys().collect::<Vec<&u8>>();
        forks.sort();
        for fork in forks {
            data.extend_from_slice(&self.forks.get(fork).unwrap().marshal_binary()?);
        }

        // get the slice of the data vector offset by the obfuscation key length until the end of the vector
        // this is the data to perform xor encryption on with the obfuscation key using encrypt_decrypt
        let to_encrypt = data[NODE_OBFUSCATION_KEY_SIZE..].to_vec();
        data[NODE_OBFUSCATION_KEY_SIZE..]
            .copy_from_slice(&encrypt_decrypt(&to_encrypt, &obfuscation_key));

        // return the data vector
        Ok(data)
    }

    fn unmarshal_binary(&mut self, data: &mut [u8]) -> Result<(), String> {
        // if the data length is less than the header length, return invalid input
        if data.len() < NODE_HEADER_SIZE {
            return Err("Data length is less than the header length".to_string());
        }

        // get the obfuscation key from the data vector and copy it to the node
        self.obfuscation_key = data[..NODE_OBFUSCATION_KEY_SIZE].to_vec();

        // perform xor decryption on the data vector with the obfuscation key using encrypt_decrypt

        let to_decrypt = data[NODE_OBFUSCATION_KEY_SIZE..].to_vec();
        data[NODE_OBFUSCATION_KEY_SIZE..]
            .copy_from_slice(&encrypt_decrypt(&to_decrypt, &self.obfuscation_key));

        // get the version hash from the data vector
        let version_hash =
            data[NODE_OBFUSCATION_KEY_SIZE..NODE_OBFUSCATION_KEY_SIZE + VERSION_HASH_SIZE].to_vec();

        // if the version hash is equal to the version hash for version 0.1
        if version_hash == hex::decode(VERSION_HASH_01).unwrap()[..31].to_vec() {
            // process version 0.1

            // get the ref_bytes_size from the data vector
            let ref_bytes_size = data[NODE_HEADER_SIZE - 1];

            // get the node entry from the data vector and copy it to the node
            self.entry =
                data[NODE_HEADER_SIZE..NODE_HEADER_SIZE + ref_bytes_size as usize].to_vec();

            let mut offset = NODE_HEADER_SIZE + ref_bytes_size as usize;

            // get the index from the data vector
            let index = BitField::from_slice(&data[offset..offset + 32]);
            offset += 32;

            for b in 0..=(u8::MAX as u8) {
                if index.get(b) {
                    let mut f = Fork::default();

                    if data.len() < offset + NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size as usize
                    {
                        return Err(format!(
                            "Not enough bytes for node fork: {} ({}) on byte '{:x}' (v1)",
                            data.len() - offset,
                            NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size as usize,
                            b
                        ));
                    }

                    // get the data to be unmarshaled from the data vector
                    let mut to_unmarshal = data
                        [offset..offset + NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size as usize]
                        .to_vec();
                    f.unmarshal_binary(to_unmarshal.as_mut_slice())?;

                    self.forks.insert(b, f);
                    offset += NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size as usize;
                }
            }

            // return the node
            Ok(())
        } else if version_hash == hex::decode(VERSION_HASH_02).unwrap()[..31].to_vec() {
            // process version 0.2

            // get the ref_bytes_size from the data vector
            let ref_bytes_size = data[NODE_HEADER_SIZE - 1];

            // get the node entry from the data vector and copy it to the node
            self.entry =
                data[NODE_HEADER_SIZE..NODE_HEADER_SIZE + ref_bytes_size as usize].to_vec();
            let mut offset = NODE_HEADER_SIZE + ref_bytes_size as usize; // skip entry

            // Currently we don't persist the root nodeType when we marshal the manifest, as a result
            // the root nodeType information is lost on Unmarshal. This causes issues when we want to
            // perform a path 'Walk' on the root. If there is more than 1 fork, the root node type
            // is an edge, so we will deduce this information from index byte array
            if data[offset..offset + 32].iter().any(|&b| b != 0) && !self.is_edge_type() {
                self.make_edge();
            }

            self.forks = Default::default();

            // get the index from the data vector
            let index = BitField::from_slice(&data[offset..offset + 32]);

            offset += 32;
            for b in 0..=(u8::MAX as u8) {
                if index.get(b) {
                    let mut f = Fork::default();

                    if data.len() < offset + NODE_FORK_TYPE_BYTES_SIZE {
                        return Err(format!(
                            "Not enough bytes for node fork: {} ({}) on byte '{:x}' (v2)",
                            data.len() - offset,
                            NODE_FORK_TYPE_BYTES_SIZE,
                            b
                        ));
                    }

                    // get the node type from the data vector
                    let node_type = data[offset];

                    let mut node_fork_size = NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size as usize;

                    // if the node type is with metadata, then we need to unmarshal the metadata
                    if (node_type & NT_WITH_METADATA) == NT_WITH_METADATA {
                        if data.len()
                            < offset
                                + NODE_FORK_PRE_REFERENCE_SIZE
                                + ref_bytes_size as usize
                                + NODE_FORK_METADATA_BYTES_SIZE
                        {
                            return Err(format!(
                                "Not enough bytes for node fork: {} ({}) on byte '{:x} (v2 with metadata)'",
                                data.len() - offset,
                                NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size as usize + NODE_FORK_METADATA_BYTES_SIZE,
                                b
                            ));
                        }

                        // get the metadata bytes size from the data vector from bigendian u16 format
                        let metadata_bytes_size = u16::from_be_bytes(
                            data[offset + node_fork_size
                                ..offset + node_fork_size + NODE_FORK_METADATA_BYTES_SIZE]
                                .try_into()
                                .unwrap(),
                        );

                        node_fork_size += NODE_FORK_METADATA_BYTES_SIZE;
                        node_fork_size += metadata_bytes_size as usize;

                        // unmarshall the fork
                        let mut to_unmarshal = data[offset..offset + node_fork_size].to_vec();
                        f.unmarshal_binary_02(
                            to_unmarshal.as_mut_slice(),
                            ref_bytes_size.into(),
                            metadata_bytes_size.into(),
                        )?
                    } else {
                        if data.len()
                            < offset + NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size as usize
                        {
                            return Err(format!(
                                "Not enough bytes for node fork: {} ({}) on byte '{:x}'",
                                data.len() - offset,
                                NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size as usize,
                                b
                            ));
                        }

                        // unmarshall the fork
                        let mut to_unmarshal = data[offset..offset + node_fork_size].to_vec();
                        f.unmarshal_binary(to_unmarshal.as_mut_slice())?;
                    }

                    self.forks.insert(b, f);
                    offset += node_fork_size;
                }
            }

            // return
            Ok(())
        } else {
            // return invalid input
            Err("Invalid version hash".to_string())
        }
    }
}

impl Marshal for Fork {
    type Item = Fork;
    fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        let r = self.node.ref_.as_slice();
        // check the length of the ref_ vector
        if r.len() > 256 {
            return Err(format!("node reference size > 256: {} ({})", r.len(), 256));
        }

        // create a vector to store the marshaled fork
        let mut data = Vec::new();

        // append the node type and prefix length to the vector
        data.push(self.node.node_type);
        data.push(self.prefix.len().try_into().unwrap());

        // append the prefix to the vector
        let mut prefix = self.prefix.clone();
        prefix.resize(NODE_PREFIX_MAX_SIZE, 0);

        data.extend_from_slice(&prefix);

        // append the ref_ to the vector
        data.extend_from_slice(r);

        if self.node.is_with_metadata_type() {
            // using json encoding to marshal the metadata
            let mut metadata_json_bytes = serde_json::to_string(&self.node.metadata).unwrap();
            // get the metadata size in bytes
            let metadata_bytes_size_with_size =
                metadata_json_bytes.len() + NODE_FORK_METADATA_BYTES_SIZE;

            let padding = match metadata_bytes_size_with_size {
                x if x < NODE_OBFUSCATION_KEY_SIZE => {
                    NODE_OBFUSCATION_KEY_SIZE - metadata_bytes_size_with_size
                }
                x if x > NODE_OBFUSCATION_KEY_SIZE => {
                    (NODE_OBFUSCATION_KEY_SIZE - metadata_bytes_size_with_size)
                        % NODE_OBFUSCATION_KEY_SIZE
                }
                _ => 0,
            };

            // add the padding to the metadata_json_bytes
            for _ in 0..padding {
                metadata_json_bytes.push('\n');
            }

            // make sure the metadata size is less than the u16 size
            if metadata_bytes_size_with_size > u16::MAX as usize {
                return Err(format!(
                    "metadata size too large {} ({})",
                    metadata_bytes_size_with_size,
                    u16::MAX
                ));
            }

            // convert metadata_bytes_size_with_size to u16
            let metadata_bytes_size_with_size_u16: u16 =
                metadata_bytes_size_with_size.try_into().unwrap();

            // append the metadata_bytes_size_with_size_u16 to the vector
            data.extend_from_slice(&metadata_bytes_size_with_size_u16.to_be_bytes());

            // append the metadata to the vector
            data.extend_from_slice(metadata_json_bytes.as_bytes());
        }

        // return the marshaled fork
        Ok(data)
    }

    fn unmarshal_binary(&mut self, data: &mut [u8]) -> Result<(), String> {
        let node_type = data[0];
        let prefix_length = data[1];

        // if prefix length is invalid, return error
        if prefix_length as usize == 0 || prefix_length as usize > NODE_PREFIX_MAX_SIZE {
            return Err(format!(
                "Invalid prefix length (fork V1): {}",
                prefix_length
            ));
        }

        // set fork prefix
        self.prefix =
            (data[NODE_FORK_HEADER_SIZE..NODE_FORK_HEADER_SIZE + prefix_length as usize]).to_vec();

        // set node from new node reference
        self.node = Node::new_node_ref(&data[NODE_FORK_PRE_REFERENCE_SIZE..]);

        // set node type
        self.node.node_type = node_type;

        Ok(())
    }
}

impl MarshalV2 for Fork {
    type Item = Fork;

    fn unmarshal_binary_02(
        &mut self,
        data: &mut [u8],
        ref_bytes_size: usize,
        metadata_bytes_size: usize,
    ) -> Result<(), String> {
        let node_type = data[0];
        let prefix_length = data[1];

        // if prefix length is invalid, return error
        if prefix_length as usize == 0 || prefix_length as usize > NODE_PREFIX_MAX_SIZE {
            return Err(format!(
                "Invalid prefix length (fork V2): {}",
                prefix_length
            ));
        }

        // set fork prefix
        self.prefix =
            (data[NODE_FORK_HEADER_SIZE..NODE_FORK_HEADER_SIZE + prefix_length as usize]).to_vec();
        self.node = Node::new_node_ref(
            &data[NODE_FORK_PRE_REFERENCE_SIZE..NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size],
        );
        self.node.node_type = node_type;

        // if there is metadata, unmarshal it
        if metadata_bytes_size > 0 {
            let metadata_bytes = &data
                [NODE_FORK_PRE_REFERENCE_SIZE + ref_bytes_size + NODE_FORK_METADATA_BYTES_SIZE..];
            let metadata = serde_json::from_slice(metadata_bytes).unwrap();
            self.node.metadata = metadata;
        }

        Ok(())
    }
}

// a struct containing a field called bits that is 256 bits long
#[derive(Debug, Clone, PartialEq, Eq)]
struct BitField {
    bits: [u8; 32],
}

impl BitField {
    pub fn new() -> Self {
        BitField { bits: [0; 32] }
    }

    // return the bitfield as a slice of bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.bits
    }

    // set the bitfield to the given slice of bytes
    pub fn set_from_bytes(&mut self, slice: &[u8]) {
        self.bits.copy_from_slice(slice);
    }

    // create a new bitfield from the given slice of bytes
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bitfield = BitField::new();
        bitfield.set_from_bytes(slice);
        bitfield
    }

    // set the bit at the given index to 1
    pub fn set(&mut self, i: u8) {
        self.bits[i as usize / 8] |= 1 << (i % 8);
    }

    // get whether the bit at the given index is greater than 0
    // TODO: This potentially does not work
    pub fn get(&self, i: u8) -> bool {
        self.bits[i as usize / 8] & (1 << (i % 8)) != 0
    }
}

// encrypt_decrypt runs a XOR operation on the data with the given key.
fn encrypt_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = Vec::<u8>::new();
    for (i, byte) in data.iter().enumerate() {
        output.push(*byte ^ key[i % key.len()]);
    }
    assert_eq!(output.len(), data.len());
    output
}

#[cfg(test)]
mod tests {}
