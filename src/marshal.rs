use const_format::concatcp;
use rand::RngCore;

use crate::{
    node::{Fork, Node},
    NFS_HEADER, NFS_METADATA, NFS_NODE_TYPE, NFS_PREFIX_MAX_SIZE, NFS_PRE_REFERENCE, NHS_FULL,
    NHS_OBFUSCATION_KEY, NHS_VERSION_HASH, NT_WITH_METADATA,
};

const VERSION_NAME: &str = "mantaray";
const VERSION_CODE_01: &str = "0.1";
const VERSION_CODE_02: &str = "0.2";
const VERSION_SEPARATOR: &str = ":";
// "mantaray:0.1"
const VERSION_STRING_01: &str = concatcp!(VERSION_NAME, VERSION_SEPARATOR, VERSION_CODE_01);
// pre-calculated version string, Keccak-256
const VERSION_HASH_01: &str = "025184789d63635766d78c41900196b57d7400875ebe4d9b5d1e76bd9652a9b7";
// "mantaray:0.2"
const VERSION_STRING_02: &str = concatcp!(VERSION_NAME, VERSION_SEPARATOR, VERSION_CODE_02);
// pre-calculated version string, Keccak-256
const VERSION_HASH_02: &str = "5768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f7b";

pub trait Marshal {
    type Item;

    fn marshal_binary(&mut self) -> Result<Vec<u8>, String>;
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

    fn marshal_binary(&mut self) -> Result<Vec<u8>, String> {
        // if forks are emtpy, return invalid input
        if self.forks.is_empty() {
            return Err("Node has no forks".to_string());
        }

        // define an empty vector to store the marshaled data
        let mut data = Vec::new();

        // header of bytes at length NFS_HEADER
        let mut header: Vec<u8> = vec![0; NFS_HEADER];

        // generate an obfuscation key if not provided
        if self.obfuscation_key.is_empty() {
            let mut obfuscation_key = vec![0; NHS_OBFUSCATION_KEY];
            rand::thread_rng().fill_bytes(&mut obfuscation_key);
            self.obfuscation_key = obfuscation_key;
        }

        // copy the obfuscation key to the header
        header[..NHS_OBFUSCATION_KEY].copy_from_slice(&self.obfuscation_key);

        // copy the version hash to the header
        header[NHS_OBFUSCATION_KEY..NHS_OBFUSCATION_KEY + NHS_VERSION_HASH]
            .copy_from_slice(VERSION_HASH_02.as_bytes());

        // set the ref_bytes_size in the header
        header[NHS_OBFUSCATION_KEY + NHS_VERSION_HASH] = self.ref_bytes_size as u8;

        // copy the header to the data vector
        data.extend_from_slice(&header);

        // append the node entry to the data vector
        data.extend_from_slice(&self.entry);

        // index

        // create an bitfield to store the index
        let mut index = BitField::new();

        // iterate over the forks and set the index bitfield
        for fork in 0..self.forks.len() {
            index.set(fork);
        }

        // append the index to the data vector
        data.extend_from_slice(&index.to_bytes());

        // iterate over the forks set in the indices and append the fork to the data vector
        for fork in 0..self.forks.len() {
            data.extend_from_slice(
                &self
                    .forks
                    .get_mut(&(fork as u8))
                    .unwrap()
                    .marshal_binary()?,
            );
        }

        // get the slice of the data vector offset by the obfuscation key length until the end of the vector
        // this is the data to perform xor encryption on with the obfuscation key using encrypt_decrypt
        let to_encrypt = data[NHS_OBFUSCATION_KEY..].to_vec();
        data[NHS_OBFUSCATION_KEY..]
            .copy_from_slice(&encrypt_decrypt(&to_encrypt, &self.obfuscation_key));

        // return the data vector
        Ok(data)
    }

    fn unmarshal_binary(&mut self, data: &mut [u8]) -> Result<(), String> {
        // if the data length is less than the header length, return invalid input
        if data.len() < NFS_HEADER {
            return Err("Data length is less than the header length".to_string());
        }

        // get the obfuscation key from the data vector and copy it to the node
        self.obfuscation_key = data[..NHS_OBFUSCATION_KEY].to_vec();

        // perform xor decryption on the data vector with the obfuscation key using encrypt_decrypt
        let to_decrypt = data[NHS_OBFUSCATION_KEY..].to_vec();
        data[NHS_OBFUSCATION_KEY..]
            .copy_from_slice(&encrypt_decrypt(&to_decrypt, &self.obfuscation_key));

        // get the version hash from the data vector
        let version_hash =
            data[NHS_OBFUSCATION_KEY..NHS_OBFUSCATION_KEY + NHS_VERSION_HASH].to_vec();

        // if the version hash is equal to the version hash for version 0.1
        if version_hash == VERSION_HASH_01.as_bytes().to_vec() {
            // process version 0.1

            // get the ref_bytes_size from the data vector
            let ref_bytes_size = data[NHS_FULL - 1];

            // get the node entry from the data vector and copy it to the node
            self.entry = data[NHS_FULL..NHS_FULL + ref_bytes_size as usize].to_vec();

            let mut offset = NHS_FULL + ref_bytes_size as usize;

            // get the index from the data vector
            let index = BitField::from_slice(&data[offset..offset + 32]);

            offset += 32;
            for b in 0..=(u8::MAX as u8) {
                if index.get(b) {
                    let mut f = Fork::default();

                    if data.len() < offset + NFS_PRE_REFERENCE + ref_bytes_size as usize {
                        return Err(format!(
                            "Not enough bytes for node fork: {} ({}) on byte '{:x}'",
                            data.len() - offset,
                            NFS_PRE_REFERENCE + ref_bytes_size as usize,
                            b
                        ));
                    }

                    // get the data to be unmarshaled from the data vector
                    let mut to_unmarshal =
                        data[offset..offset + NFS_PRE_REFERENCE + ref_bytes_size as usize].to_vec();
                    f.unmarshal_binary(to_unmarshal.as_mut_slice())?;

                    self.forks.insert(b, f);
                    offset += NFS_PRE_REFERENCE + ref_bytes_size as usize;
                }
            }

            // return the node
            Ok(())
        } else if version_hash == VERSION_HASH_02.as_bytes().to_vec() {
            // process version 0.2

            // get the ref_bytes_size from the data vector
            let ref_bytes_size = data[NHS_FULL - 1];

            // get the node entry from the data vector and copy it to the node
            self.entry = data[NHS_FULL..NHS_FULL + ref_bytes_size as usize].to_vec();
            let mut offset = NHS_FULL + ref_bytes_size as usize; // skip entry

            // Currently we don't persist the root nodeType when we marshal the manifest, as a result
            // the root nodeType information is lost on Unmarshal. This causes issues when we want to
            // perform a path 'Walk' on the root. If there is more than 1 fork, the root node type
            // is an edge, so we will deduce this information from index byte array

            // if data[offset:offset+32] is all zeros, then the root node type is an edge
            if data[offset..offset + 32].iter().all(|&b| b == 0) && !self.is_edge_type() {
                self.make_edge();
            }

            self.forks = Default::default();

            // get the index from the data vector
            let index = BitField::from_slice(&data[offset..offset + 32]);

            for b in 0..=(u8::MAX as u8) {
                if index.get(b) {
                    let mut f = Fork::default();

                    if data.len() < offset + NFS_NODE_TYPE {
                        return Err(format!(
                            "Not enough bytes for node fork: {} ({}) on byte '{:x}'",
                            data.len() - offset,
                            NFS_PRE_REFERENCE,
                            b
                        ));
                    }

                    // get the node type from the data vector
                    let node_type = data[offset];

                    let mut node_fork_size = NFS_PRE_REFERENCE + ref_bytes_size as usize;

                    // if the node type is with metadata, then we need to unmarshal the metadata
                    if node_type & NT_WITH_METADATA == NT_WITH_METADATA {
                        if data.len()
                            < offset + NFS_PRE_REFERENCE + ref_bytes_size as usize + NFS_METADATA
                        {
                            return Err(format!(
                                "Not enough bytes for node fork: {} ({}) on byte '{:x}'",
                                data.len() - offset,
                                NFS_PRE_REFERENCE + ref_bytes_size as usize + NFS_METADATA,
                                b
                            ));
                        }

                        // get the metadata bytes size from the data vector from bigendian u16 format
                        let metadata_bytes_size = u16::from_be_bytes(
                            data[offset + node_fork_size..offset + node_fork_size + NFS_METADATA]
                                .try_into()
                                .unwrap(),
                        );

                        node_fork_size += NFS_METADATA;
                        node_fork_size += metadata_bytes_size as usize;

                        // unmarshall the fork
                        let mut to_unmarshal = data[offset..offset + node_fork_size].to_vec();
                        f.unmarshal_binary_02(
                            to_unmarshal.as_mut_slice(),
                            ref_bytes_size.into(),
                            metadata_bytes_size.into(),
                        )?
                    } else {
                        if data.len() < offset + NFS_PRE_REFERENCE + ref_bytes_size as usize {
                            return Err(format!(
                                "Not enough bytes for node fork: {} ({}) on byte '{:x}'",
                                data.len() - offset,
                                NFS_PRE_REFERENCE + ref_bytes_size as usize,
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
            return Err("Invalid version hash".to_string());
        }
    }
}

impl Marshal for Fork {
    type Item = Fork;
    fn marshal_binary(&mut self) -> Result<Vec<u8>, String> {
        let r = self.node.ref_.as_slice();
        // check the length of the ref_ vector
        if r.len() > 256 {
            return Err(format!("node reference size > 256: {} ({})", r.len(), 256));
        }

        // create a vector to store the marshaled fork
        let mut v = Vec::new();

        // append the node type and prefix length to the vector
        v.push(self.node.node_type);
        v.push(self.prefix.len() as u8);

        // append the prefix to the vector
        v.extend_from_slice(&self.prefix);

        // append the ref_ to the vector
        v.extend_from_slice(&r);

        if self.node.is_with_metadata_type() {
            // using json encoding to marshal the metadata
            let mut metadata_json_bytes = serde_json::to_string(&self.node.metadata).unwrap();
            // get the metadata size in bytes
            let metadata_bytes_size_with_size = metadata_json_bytes.len() + NFS_METADATA;

            // calcuate the amount of padding to add
            let padding = if metadata_bytes_size_with_size < NHS_OBFUSCATION_KEY {
                NHS_OBFUSCATION_KEY - metadata_bytes_size_with_size
            } else if metadata_bytes_size_with_size > NHS_OBFUSCATION_KEY {
                (NHS_OBFUSCATION_KEY - metadata_bytes_size_with_size) & NHS_OBFUSCATION_KEY
            } else {
                0
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
            v.extend_from_slice(&metadata_bytes_size_with_size_u16.to_be_bytes());

            // append the metadata to the vector
            v.extend_from_slice(metadata_json_bytes.as_bytes());
        }

        // return the marshaled fork
        Ok(v)
    }

    fn unmarshal_binary(&mut self, data: &mut [u8]) -> Result<(), String> {
        let node_type = data[0];
        let prefix_length = data[1];

        // if prefix length is invalid, return error
        if prefix_length as usize > NFS_PREFIX_MAX_SIZE || prefix_length as usize == 0 {
            return Err(format!("Invalid prefix length: {}", prefix_length));
        }

        // set fork prefix
        self.prefix = (&data[NFS_HEADER..NFS_HEADER + prefix_length as usize]).to_vec();

        // set node from new node reference
        self.node = Node::new_node_ref(&data[NFS_PRE_REFERENCE..]);

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
        if prefix_length as usize > NFS_PREFIX_MAX_SIZE || prefix_length as usize == 0 {
            return Err(format!("Invalid prefix length: {}", prefix_length));
        }

        // set fork prefix
        self.prefix = (&data[NFS_HEADER..NFS_HEADER + prefix_length as usize]).to_vec();
        self.node =
            Node::new_node_ref(&data[NFS_PRE_REFERENCE..NFS_PRE_REFERENCE + ref_bytes_size]);
        self.node.node_type = node_type;

        // if there is metadata, unmarshal it
        if metadata_bytes_size > 0 {
            let metadata_bytes = &data[NFS_PRE_REFERENCE + ref_bytes_size + NFS_METADATA..];
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
    pub fn from_bytes(&mut self, slice: &[u8]) {
        self.bits.copy_from_slice(slice);
    }

    // create a new bitfield from the given slice of bytes
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bitfield = BitField::new();
        bitfield.from_bytes(slice);
        bitfield
    }

    // set the bit at the given index to 1
    pub fn set(&mut self, i: usize) {
        self.bits[i / 8] |= 1 << (i % 8);
    }

    // get whether the bit at the given index is greater than 0
    // TODO: This potentially does not work
    pub fn get(&self, i: u8) -> bool {
        self.bits[i as usize / 8] & (1 << (i % 8)) != 0
    }

    // return the indices of the set bits in the bitfield
    pub fn indices(&self) -> Vec<u8> {
        let mut indices = Vec::<u8>::new();
        for i in 0..self.bits.len() as u8 {
            for j in 0..8 {
                if self.get(i * 8 + j) {
                    indices.push(i * 8 + j);
                }
            }
        }
        indices
    }
}

// encrypt_decrypt runs a XOR operation on the data with the given key.
fn encrypt_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = Vec::<u8>::new();
    for (i, byte) in data.iter().enumerate() {
        output.push(*byte ^ key[i % key.len()]);
    }
    output
}

// #[test]
// fn serde() {
//     let rand_address = rand::thread_rng().gen::<[u8; 32]>();
//     let mut node = Node::default();
//     node.entry = rand_address.as_slice().to_vec();

//     let mut serialised = node.marshal_binary().unwrap();
//     eprintln!("{:x?}", serialised);

//     let mut node_compare = Node::default();
//     node_compare.unmarshal_binary(&mut serialised).unwrap();

//     assert_eq!(node.entry, node_compare.entry);

//     let (mut node, _) = get_sample_mantaray_node().unwrap();
//     let mut serialised = node.marshal_binary().unwrap();

//     let mut node_compare = Node::default();
//     node_compare.unmarshal_binary(&mut serialised).unwrap();

//     assert_eq!(node.entry, node_compare.entry);
// }
