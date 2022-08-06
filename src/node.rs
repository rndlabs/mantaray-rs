use std::collections::HashMap;

use async_recursion::async_recursion;
use serde::*;
use serde_with::serde_as;

#[derive(Debug, Deserialize, Clone, Default)]
struct UploadedReference {
    reference: String,
}

use bitvec::array::BitArray;
use bitvec::prelude::*;
use bitvec::BitArr;

const PATH_SEPARATOR: &str = "/";

const NFS_NODE_TYPE: usize = 1;
const NFS_PREFIX_LENGTH: usize = 1;
const NFS_PRE_REFERENCE: usize = 32;
const NFS_METADATA: usize = 2;
const NFS_HEADER: usize = NFS_NODE_TYPE + NFS_PREFIX_LENGTH;
const NFS_PREFIX_MAX_SIZE: usize = NFS_PRE_REFERENCE - NFS_HEADER;

const NHS_OBFUSCATION_KEY: usize = 32;
const NHS_VERSION_HASH: usize = 31;
const NHS_REF_BYTES: usize = 1;
const NHS_FULL: usize = NHS_OBFUSCATION_KEY + NHS_VERSION_HASH + NHS_REF_BYTES;

const NT_VALUE: u8 = 2;
const NT_EDGE: u8 = 4;
const NT_WITH_PATH_SEPARATOR: u8 = 8;
const NT_WITH_METADATA: u8 = 16;
const NT_MASK: u8 = 255;

// const VERSION_NAME: &str = "mantaray";
// const VERSION_CODE_01: &str = "0.1";
// const VERSION_CODE_02: &str = "0.2";
// const VERSION_SEPARATOR: &str = ":";
// "mantaray:0.1"
// const VERSION_STRING_01: &str = concatcp!(VERSION_NAME, VERSION_SEPARATOR, VERSION_CODE_01);
// pre-calculated version string, Keccak-256
const VERSION_HASH_01: &str = "025184789d63635766d78c41900196b57d7400875ebe4d9b5d1e76bd9652a9b7";
// "mantaray:0.2"
// const VERSION_STRING_02: &str = concatcp!(VERSION_NAME, VERSION_SEPARATOR, VERSION_CODE_02);
// pre-calculated version string, Keccak-256
const VERSION_HASH_02: &str = "5768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f7b";

// zero byte u8 array 32 bytes long
const ZERO_BYTES: [u8; 32] = [0; 32];

pub struct RecursiveSaveReturnType {
    pub reference: Vec<u8>,
    pub changed: bool,
}

pub struct WithMetadataOptions {
    ref_bytes_size: usize,
    metadata_byte_size: usize,
}

pub struct UploadOptions {
    pub host: String,
    pub stamp: String,
    pub tag: String,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MantarayFork {
    #[serde_as(as = "serde_with::hex::Hex")]
    prefix: Vec<u8>,
    node: MantarayNode,
}

impl MantarayFork {
    pub fn serialize(&self) -> Vec<u8> {
        let mut output = Vec::<u8>::new();

        // node_type
        output.push(self.node.node_type);
        // prefix_length
        output.push(self.prefix.len() as u8);

        // prefix bytes
        let mut prefix_output: [u8; NFS_PREFIX_MAX_SIZE] = [0; NFS_PREFIX_MAX_SIZE];
        prefix_output[..self.prefix.len()].copy_from_slice(&self.prefix);

        // if content address length is 32 or 64, add to output vector
        if self.node.cac.len() == 32 || self.node.cac.len() == 64 {
            output.extend_from_slice(&self.node.cac);
        } else {
            panic!("Cannot serialize MantarayFork because it does not have a content address");
        }

        // metadata
        if self.node.is_with_metadata_type() {
            let json = serde_json::to_string(&self.node.metadata).unwrap();
            // metadata size
            output.extend((json.len() as u16).to_be_bytes());
            // metadata string
            output.extend(json.as_bytes());
        }

        output
    }

    pub fn deserialize(
        data: &[u8],
        obfuscation_key: [u8; NHS_OBFUSCATION_KEY],
        options: Option<WithMetadataOptions>,
    ) -> MantarayFork {
        let node_type = data[0];
        let prefix_length: usize = data[1].into();

        if prefix_length == 0 || prefix_length > NFS_PREFIX_MAX_SIZE {
            panic!(
                "Prefix length of fork is greater than {}. Got: {}",
                NFS_PREFIX_MAX_SIZE, prefix_length
            );
        }

        let prefix = &data[NFS_HEADER..NFS_HEADER + prefix_length].to_vec();

        let node = match options {
            Some(metadata_options) => {
                if metadata_options.metadata_byte_size > 0 {
                    let entry = data
                        [NFS_PRE_REFERENCE..NFS_PRE_REFERENCE + metadata_options.ref_bytes_size]
                        .to_owned()
                        .into_boxed_slice();

                    let start_metadata: usize =
                        NFS_PRE_REFERENCE + metadata_options.ref_bytes_size + NFS_METADATA;
                    let metadata_bytes =
                        &data[start_metadata..start_metadata + metadata_options.metadata_byte_size];
                    let map: HashMap<String, String> =
                        match serde_json::from_slice::<HashMap<String, String>>(metadata_bytes) {
                            Ok(de) => de,
                            Err(_) => panic!("Unable to deserialize"),
                        };

                    MantarayNode {
                        node_type,
                        obfuscation_key,
                        cac: [].to_vec(),
                        entry: entry.to_vec(),
                        metadata: map,
                        forks: HashMap::<u8, MantarayFork>::new(),
                    }
                } else {
                    todo!()
                }
            }
            None => {
                let entry = match data.len() - NFS_PRE_REFERENCE {
                    32 | 64 => data[NFS_PRE_REFERENCE..].to_owned().into_boxed_slice(),
                    _ => panic!("Invalid"),
                };

                MantarayNode {
                    node_type,
                    obfuscation_key,
                    cac: [].to_vec(),
                    entry: entry.to_vec(),
                    metadata: HashMap::<String, String>::new(),
                    forks: HashMap::<u8, MantarayFork>::new(),
                }
            }
        };

        MantarayFork {
            prefix: prefix.to_vec(),
            node,
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MantarayNode {
    node_type: u8,
    #[serde_as(as = "serde_with::hex::Hex")]
    obfuscation_key: [u8; 32],
    #[serde_as(as = "serde_with::hex::Hex")]
    cac: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    entry: Vec<u8>,
    metadata: HashMap<String, String>,
    forks: HashMap<u8, MantarayFork>,
}

// determine if a buffer of bytes is all equal to zero
fn is_zero_bytes(buffer: &[u8]) -> bool {
    buffer.iter().all(|&b| b == 0)
}

fn is_reference(buffer: &[u8]) -> bool {
    buffer.len() == 32 || buffer.len() == 64
}

// find the index at which a subslice exists within a slice
fn find_index_of_array(slice: &[u8], subslice: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i <= slice.len() - subslice.len() {
        if slice[i..i + subslice.len()].to_vec() == subslice.to_vec() {
            return Some(i);
            }
        i += 1;
        }
    None
    }

// return the common part of two slices starting from index 0
fn common(slice: &[u8], subslice: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i < slice.len() && i < subslice.len() {
        if slice[i] != subslice[i] {
            break;
        }
        i += 1;
    }
    slice[0..i].to_vec()
}

fn encrypt_decrypt(key: &[u8], data: &mut [u8]) {
    if key == ZERO_BYTES.as_slice() {
        return;
    }

    if key.len() != NHS_OBFUSCATION_KEY {
        panic!("Invalid key length");
    }

    for i in 0..data.len() {
        data[i] ^= key[i % key.len()];
    }
}

impl MantarayNode {
    // immutable access
    pub fn node_type(&self) -> u8 {
        self.node_type
    }

    pub fn obfuscation_key(&self) -> &[u8; 32] {
        &self.obfuscation_key
    }

    pub fn content_address(&self) -> &[u8] {
        &self.cac
    }

    pub fn entry(&self) -> &[u8] {
        &self.entry
    }

    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    // mutable access
    pub fn set_content_address(&mut self, content_address: &[u8]) {
        if !is_reference(content_address) {
            panic!("Wrong reference length. Entry only can be 32 or 64 length in bytes");
        }

        self.cac = content_address.to_vec();
    }

    pub fn set_entry(&mut self, entry: &[u8]) {
        if !is_reference(entry) {
            panic!("Wrong reference length. Entry only can be 32 or 64 length in bytes");
        }

        // if entry isn't just zero bytes, set to having a value.
        if !is_zero_bytes(entry) {
            self.make_value();
        }

        self.entry = entry.to_vec();
        self.make_dirty();
    }

    pub fn set_node_type(&mut self, node_type: u8) {
        self.node_type = node_type
    }

    pub fn set_obfuscation_key(&mut self, obfuscation_key: [u8; 32]) {
        self.obfuscation_key = obfuscation_key;
        self.make_dirty();
    }

    pub fn set_metadata(&mut self, metadata: HashMap<String, String>) {
        self.metadata = metadata;
        self.make_with_metadata();

        // TODO: when the mantaray node is a pointer by its metadata then
        // the node has to be with `value` type even though it has zero address
        // should get info why is `withMetadata` as type is not enough
        if self.metadata.contains_key("website-index-document")
            || self.metadata.contains_key("website-error-document")
        {
            self.make_value();
        }

        self.make_dirty();
    }

    // node type related functions
    pub fn is_value_type(&self) -> bool {
        (self.node_type & NT_VALUE) == NT_VALUE
    }

    pub fn is_edge_type(&self) -> bool {
        (self.node_type & NT_EDGE) == NT_EDGE
    }

    pub fn is_with_path_separator_type(&self) -> bool {
        (self.node_type & NT_WITH_PATH_SEPARATOR) == NT_WITH_PATH_SEPARATOR
    }

    pub fn is_with_metadata_type(&self) -> bool {
        (self.node_type & NT_WITH_METADATA) == NT_WITH_METADATA
    }

    pub fn node_type_is_with_metadata_type(node_type: &u8) -> bool {
        node_type & NT_WITH_METADATA == NT_WITH_METADATA
    }

    pub fn check_for_separator(node: &MantarayNode) -> bool {
        for fork in node.forks.values() {
            if fork.prefix.iter().any(|&v| v == 47) || Self::check_for_separator(&fork.node) {
                return true;
            }
        }

        false
    }

    fn make_value(&mut self) {
        self.node_type |= NT_VALUE
    }

    fn make_edge(&mut self) {
        self.node_type |= NT_EDGE
    }

    fn make_with_path_separator(&mut self) {
        self.node_type |= NT_WITH_PATH_SEPARATOR
    }

    fn make_with_metadata(&mut self) {
        self.node_type |= NT_WITH_METADATA
    }

    fn make_not_with_path_separator(&mut self) {
        self.node_type &= NT_MASK ^ NT_WITH_PATH_SEPARATOR
    }

    fn update_with_path_separator(&mut self, path: &[u8]) {
        // TODO: it is not clear why the `withPathSeparator` is not related to the first path element - should
        // get info about it.
        let path = match String::from_utf8(path.to_vec()) {
            Ok(s) => s,
            Err(_) => panic!("Decoding of string is malformed"),
        };

        // eprintln!("Path is: {}", path);

        match path.find(PATH_SEPARATOR) {
            Some(_) => self.make_with_path_separator(),
            None => self.make_not_with_path_separator(),
        };
    }

    // BL methods

    pub fn add_fork(&mut self, path: &[u8], entry: &[u8], metadata: HashMap<String, String>) {
        if path.is_empty() {
            self.set_entry(entry);

            if !metadata.is_empty() {
                self.set_metadata(metadata);
            }

            self.make_dirty();

            return;
        }

        let obfuscation_key = self.obfuscation_key;

        let (path, fork) = match self.forks.get_mut(&path[0]) {
            None => match path.len() > NFS_PREFIX_MAX_SIZE {
                true => {
                    let prefix = &path[0..NFS_PREFIX_MAX_SIZE];
                    let rest = &path[NFS_PREFIX_MAX_SIZE..];

                    let mut node = MantarayNode {
                        node_type: 0,
                        obfuscation_key,
                        cac: [].to_vec(),
                        entry: ZERO_BYTES.to_vec(),
                        metadata: HashMap::<String, String>::new(),
                        forks: HashMap::<u8, MantarayFork>::new(),
                    };

                    node.add_fork(rest, entry, metadata);
                    node.update_with_path_separator(prefix);

                    (
                        path[0],
                        MantarayFork {
                            prefix: prefix.to_vec(),
                            node,
                        },
                    )
                }
                false => {
                    let mut node = MantarayNode {
                        node_type: 0,
                        obfuscation_key,
                        cac: [].to_vec(),
                        entry: entry.to_vec(),
                        metadata,
                        forks: HashMap::<u8, MantarayFork>::new(),
                    };

                    node.update_with_path_separator(path);

                    (
                        path[0],
                        MantarayFork {
                            prefix: path.to_vec(),
                            node,
                        },
                    )
                }
            },
            Some(fork) => {
                let common_path = common(&fork.prefix, path);
                let rest_path = &fork.prefix[common_path.len()..];

                let node_clone = fork.node.clone();
                let mut new_node = fork.node.clone();

                if !rest_path.is_empty() {
                    // move current common prefix node
                    new_node = MantarayNode {
                        node_type: 0,
                        obfuscation_key,
                        cac: [].to_vec(),
                        entry: ZERO_BYTES.to_vec(),
                        metadata: HashMap::<String, String>::new(),
                        forks: HashMap::<u8, MantarayFork>::new(),
                    };

                    fork.node.update_with_path_separator(rest_path);

                    new_node.forks.insert(
                        rest_path[0],
                        MantarayFork {
                            prefix: rest_path.to_vec(),
                            node: node_clone,
                        },
                    );

                    new_node.make_edge();

                    // if common path is full path new node is value type
                    if path.len() == common_path.len() {
                        new_node.make_value();
                    }
                }

                // NOTE: special case on edge split
                // new_node will be the common path edge node
                // TODO: change it on the bee side! -> new_node is the edge (parent) node of the newly
                // created path, so `common_path` should be passed instead of `path`.
                new_node.update_with_path_separator(&common_path);
                // new_node's prefix is a subset of the given `path`, here the desire fork will be added
                // with the truncated path
                new_node.add_fork(&path[common_path.len()..], entry, metadata);

                (
                    path[0],
                    MantarayFork {
                        prefix: common_path.to_vec(),
                        node: new_node,
                    },
                )
            }
        };

        self.forks.insert(path, fork);
        self.make_edge();
        self.make_dirty();
    }

    pub fn get_fork_at_path(&self, path: &[u8]) -> &MantarayFork {
        if path.is_empty() {
            panic!("Empty path");
        }

        let fork = self.forks.get(&path[0]);

        match fork {
            Some(f) => {
                let prefix_index = find_index_of_array(path, &fork.unwrap().prefix);

                match prefix_index {
                    Some(_) => {
                        let rest = &path[f.prefix.len()..];
                        if rest.is_empty() {
                            f
                        } else {
                            fork.unwrap().node.get_fork_at_path(rest)
                        }
                    }
                    None => {
                        panic!(
                            "Path has not been found in the manifest. Remaining path on lookup {} on prefix: {}", 
                            String::from_utf8(path[..].to_vec()).unwrap(),
                            String::from_utf8(fork.unwrap().prefix[..].to_vec()).unwrap()
                        );
                    }
                }
            }
            None => panic!(
                "Path has not been found in the manifest. Remaining path on lookup: {}",
                String::from_utf8(path.to_vec()).unwrap()
            ),
        }
    }

    pub fn remove_path(&mut self, path: Vec<u8>) {
        if path.is_empty() {
            panic!("Empty path");
        }

        if self.forks.is_empty() {
            panic!("Fork mapping is not defined in the manifest");
        }

        match self.forks.get_mut(&path[0]) {
            None => panic!(
                "Path has not been found in the manifest. Remaining path on lookup: {}",
                String::from_utf8(path).unwrap()
            ),
            Some(f) => {
                match find_index_of_array(&path, &f.prefix) {
                    None => {
                        panic!(
                            "Path has not been found in the manifest. Remaining path on lookup {} on prefix: {}", 
                            String::from_utf8(path[..].to_vec()).unwrap(),
                            String::from_utf8(f.prefix[..].to_vec()).unwrap()
                        );
                    },
                    Some(_) => {
                        let rest = &path[f.prefix.len()..];
                        if rest.is_empty() {
                            // full path matched
                            self.make_dirty();
                            self.forks.remove(&path[0]);
                        } else {
                            f.node.remove_path(rest.to_vec())
                        }
                    }
                    }
            },
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.cac.is_empty()
    }

    pub fn make_dirty(&mut self) {
        self.cac = [].to_vec()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, String> {
        if self.forks.is_empty() && self.entry.is_empty() {
            return Err("Entry field is empty".to_string());
        }

        let mut idx: BitArr!(for 256, in u8) = BitArray::<_>::ZERO;
        for i in self.forks.keys() {
            idx.set((*i).into(), true);
        }

        let mut fork_serializations = Vec::<Vec<u8>>::new();
        for i in 0..idx.first_zero().unwrap() {
            match self.forks.get(&(i as u8)) {
                Some(fork) => fork_serializations.push(fork.serialize()),
                None => {
                    return Err(format!(
                        "Fork indexing error: fork was not found under {} index",
                        i
                    ));
                }
            }
        }

        let mut output = Vec::new();
        // obfuscation key
        output.extend(self.obfuscation_key);
        // version hash
        output.append(&mut hex::decode(&VERSION_HASH_02[..VERSION_HASH_02.len() - 2]).unwrap());
        // reference length bytes
        output.push(match self.entry.is_empty() {
            false => match self.entry.len() {
                32 => 32,
                64 => 64,
                t => return Err(format!("Invalid entry length: {}", t)),
            },
            true => 32,
        });
        // entry
        if self.entry.is_empty() {
            output.extend(ZERO_BYTES.iter());
        } else {
            output.extend(self.entry.iter());
        }

        // add index bytes to output
        output.extend(idx.iter().map(|b| *b as u8));

        // add fork serializations to output
        output.extend(fork_serializations.iter().flat_map(|f| f.iter()));

        // encryption
        // perform XOR encryption on bytes after obfuscation key
        encrypt_decrypt(self.obfuscation_key(), &mut output[NHS_OBFUSCATION_KEY..]);

        Ok(output)
    }

    pub fn deserialize(data: &mut [u8]) -> Result<MantarayNode, String> {
        if data.len() < NHS_FULL {
            return Err("The serialised intput is too short".to_string());
        }

        let obfuscation_key = &data[0..NHS_OBFUSCATION_KEY].to_owned();
        encrypt_decrypt(obfuscation_key, &mut data[NHS_OBFUSCATION_KEY..]);

        let version_hash =
            hex::encode(&data[NHS_OBFUSCATION_KEY..NHS_OBFUSCATION_KEY + NHS_VERSION_HASH]);

        if version_hash == VERSION_HASH_01[..VERSION_HASH_01.len() - 2] {
            return Err("mantaray:0.1 is not implemented".to_string());
        }

        if version_hash == VERSION_HASH_02[..VERSION_HASH_02.len() - 2] {
            let ref_bytes_size = &data[NHS_FULL - 1];
            let mut entry = &data[NHS_FULL..NHS_FULL + *ref_bytes_size as usize];

            // FIXME: in Bee if one uploads a file on the bzz endpoint, the node under `/` gets 0 refsize
            if *ref_bytes_size == 0 {
                entry = ZERO_BYTES.as_slice();
            }

            let mut offset = NHS_FULL + *ref_bytes_size as usize;
            let index = &data[offset..offset + 32];
            // Currently we don't persist the root nodeType when we marshal the manifest, as a result
            // the root nodeType information is lost on Unmarshal. This causes issues when we want to
            // perform a path 'Walk' on the root. If there is at least 1 fork, the root node type
            // is an edge, so we will deduce this information from index byte array
            if *index == ZERO_BYTES {
                // this.makeEdge()
            }

            offset += 32;

            let mut forks: HashMap<u8, MantarayFork> = HashMap::new();

            if let Some(num_forks) = index.view_bits::<Msb0>().first_zero() {
                for fork in 0..num_forks {
                    if data.len() < offset + NFS_NODE_TYPE {
                        panic!(
                            "There is not enough size to read node_type of fork at offset {}",
                            offset
                        );
                        // return Err(format!("There is not enough size to read node_type of fork at offset {}", offset))
                    }

                    let node_type = &data[offset..offset + NFS_NODE_TYPE];
                    let mut node_fork_size: u16 =
                        (NFS_PRE_REFERENCE as u8 + *ref_bytes_size) as u16;

                    if Self::node_type_is_with_metadata_type(&node_type[0]) {
                        if data.len()
                            < offset + NFS_PRE_REFERENCE + *ref_bytes_size as usize + NFS_METADATA
                        {
                            panic!("Not enough bytes for metadata node fork at byte {}", fork);
                        }

                        let metadata_size_bytes: [u8; 2] = match &data[offset
                            + node_fork_size as usize
                            ..offset + (node_fork_size + NFS_METADATA as u16) as usize]
                            .try_into()
                        {
                            Ok(bytes) => *bytes,
                            Err(_) => return Err("metadata size malformed".to_string()),
                        };

                        let metadata_size: u16 = u16::from_be_bytes(metadata_size_bytes);
                        node_fork_size += NFS_METADATA as u16 + metadata_size;

                        forks.insert(
                            fork as u8,
                            MantarayFork::deserialize(
                                &data[offset..offset + node_fork_size as usize],
                                obfuscation_key.as_slice().try_into().unwrap(),
                                Some(WithMetadataOptions {
                                    ref_bytes_size: *ref_bytes_size as usize,
                                    metadata_byte_size: metadata_size as usize,
                                }),
                            ),
                        );
                    } else {
                        if data.len()
                            < offset + (NFS_PRE_REFERENCE + *ref_bytes_size as usize) as usize
                        {
                            panic!("There is not enough size to read fork at offset {}", offset);
                        }

                        forks.insert(
                            fork as u8,
                            MantarayFork::deserialize(
                                &data[offset..offset + node_fork_size as usize],
                                obfuscation_key.as_slice().try_into().unwrap(),
                                None,
                            ),
                        );
                    }

                    offset += node_fork_size as usize;
                }
            }

            let mut node = MantarayNode {
                node_type: match *index == ZERO_BYTES {
                    true => NT_EDGE,
                    false => 0,
                },
                obfuscation_key: obfuscation_key.as_slice().try_into().unwrap(),
                cac: [].to_vec(),
                entry: ZERO_BYTES.to_vec(),
                metadata: HashMap::new(),
                forks,
            };

            node.set_entry(entry);

            return Ok(node);
        }

        Err("Wrong mantaray version".to_string())
    }

    pub async fn load<F>(storage_loader: F, reference: &[u8]) -> Result<MantarayNode, String>
    where
        F: Fn(&[u8]) -> Vec<u8>,
    {
        if !is_reference(reference) {
            panic!("Wrong reference length. Entry only can be 32 or 64 length in bytes");
        }

        let mut data = storage_loader(reference);
        let mut node = MantarayNode::deserialize(&mut data)?;

        node.set_content_address(reference);

        Ok(node)
    }

    pub async fn upload(&self, options: &UploadOptions) -> Result<Vec<u8>, String> {
        let client = reqwest::Client::new();
        let request_url = format!("http://{}:1633/bytes", options.host);
        println!("URL: {}", request_url);

        let payload = self.serialize();
        match payload {
            Ok(payload) => {
                let res = client
                    .post(request_url)
                    .body(payload)
                    .header("swarm-postage-batch-id", &options.stamp)
                    .send();
                let reference: UploadedReference = res.await.expect("reason").json().await.unwrap();
                Ok(hex::decode(reference.reference).unwrap())
            }
            Err(e) => Err(e),
        }
    }


    pub async fn save(&mut self, options: &UploadOptions) -> Result<Vec<u8>, String> {
        // use recursive save and get the reference of the root node
        let reference = self.recursive_save(options).await?.reference;
        
        // return reference as slice
        Ok(reference.to_vec())
    }

    // asynchronous function to save the node and all its forks recursively
    #[async_recursion]
    async fn recursive_save(&mut self, options: &UploadOptions) -> Result<RecursiveSaveReturnType, String> {
        // async in box to avoid blocking main thread
        // create thread for saving each fork and wait for them to finish
        let mut threads = Vec::new();
        for fork in self.forks.values_mut() {
            threads.push(async move {
                fork.node.recursive_save(options).await
            });
        }

        // wait for all forks to finish saving
        // collect all the results and check if any changed
        let mut changed = false;
        for thread in threads {
            let result = thread.await;
            if result.unwrap().changed {
                changed = true;
            }
        }
        
        if !self.is_dirty() && !changed {
            eprintln!("No changes detected");
            return Ok(RecursiveSaveReturnType {
                reference: self.cac.clone(),
                changed: false,
            });
        }

        // save the actual manifest as well
        let reference = self.upload(options).await.unwrap();
        self.set_content_address(reference.as_slice());

        Ok(
            RecursiveSaveReturnType {
                reference,
                changed: true,
            },
        )

    }
}

#[cfg(test)]
mod tests_integration {

    use super::*;
    use reqwest::Error;

    #[derive(Debug, Deserialize, Clone, Default)]
    struct Stamps {
        stamps: Vec<Stamp>,
    }

    #[derive(Debug, Deserialize, Clone, Default)]
    pub struct Stamp {
        #[serde(rename(deserialize = "batchID"))]
        pub batch_id: String,
        #[serde(default)]
        pub utilization: u32,
        #[serde(default)]
        pub usable: bool,
        #[serde(default)]
        pub label: String,
        #[serde(default)]
        pub depth: u8,
        #[serde(default)]
        pub amount: String,
        #[serde(rename(deserialize = "bucketDepth"), default)]
        pub bucket_depth: u8,
        #[serde(rename(deserialize = "blockNumber"), default)]
        pub block_number: u32,
        #[serde(rename(deserialize = "immutableFlag"), default)]
        pub immutable_flag: bool,
        #[serde(default)]
        pub exists: bool,
        #[serde(rename(deserialize = "batchTTL"), default)]
        pub batch_ttl: i32,
    }

    async fn postage_stamp() -> Result<Stamp, Error> {
        let client = reqwest::Client::new();

        // first see if there is a stamp available
        let request_url = format!("http://127.0.0.1:1635/stamps");
        let res = client.get(request_url).send().await.unwrap();

        let stamps: Stamps = res.json().await.unwrap();
        if !stamps.stamps.is_empty() {
            // just blindly return the first stamp
            return Ok(stamps.stamps[0].clone());
        } else {
            let request_url = format!(
                "http://127.0.0.1:1635/stamps/{amount}/{depth}",
                amount = "100000",
                depth = 30
            );
            println!("{}", request_url);

            let res = client.post(request_url).send().await.unwrap();

            let stamp: Stamp = res.json().await.unwrap();
            Ok(stamp)
        }
    }

    #[tokio::test]
    pub async fn fork_removal() {
        let (mut node, paths) = crate::node::tests::get_sample_mantaray_node();
        eprintln!("Using stamp: {}", postage_stamp().await.unwrap().batch_id);

        let options = crate::node::UploadOptions {
            host: String::from("127.0.0.1"),
            stamp: postage_stamp().await.unwrap().batch_id,
            tag: String::from("test"),
        };

        // before save, there shouldn't be any content addresses
        eprintln!(
            "Before save: {}", 
            serde_json::to_string_pretty(&node).unwrap()
                .replace("\\", "")
        );

        // save
        let original_reference = node.save(&options).await.unwrap().clone();

        // before save, there shouldn't be any content addresses
        eprintln!(
            "After save: {}", 
            serde_json::to_string_pretty(&node).unwrap()
                .replace("\\", "")
        );

        eprintln!("Original reference: {}", hex::encode(&original_reference));

        // let get_check_node = || -> &MantarayNode {
        //     &node.get_fork_at_path("path1/valami/".as_bytes()).node
        // };

        // get node at fork at path1/valami/
        // let check_node_1 = &node.get_fork_at_path("path1/valami/".as_bytes()).node;


        // let mut check_node_1_keys =
        //     check_node_1.forks.keys().cloned().collect::<Vec<u8>>();
        // check_node_1_keys.sort();

        // // current forks of node
        // assert_eq!(check_node_1_keys, vec![paths[0][13], paths[1][13]]);

        // remove path_1_clone from node's path
        // node.remove_path(paths[1].clone());

        let check_node_1 = &node
            .get_fork_at_path(&Vec::from("path1/valami/".as_bytes()))
            .node;

        assert_eq!(check_node_1.is_dirty(), false);

        node.remove_path(paths[1][..].to_vec());

        let check_node_1 = &node
            .get_fork_at_path(&Vec::from("path1/valami/".as_bytes()))
            .node;


        assert_eq!(check_node_1.is_dirty(), true);

        let deleted_reference = node.save(&options).await.unwrap();

        eprintln!(
            "After deletion: {}", 
            serde_json::to_string_pretty(&node).unwrap()
                .replace("\\", "")
        );

        eprintln!("Deleted reference: {:?}", hex::encode(&deleted_reference));

        // root reference should not remain the same
        // assert_eq!(original_reference.eq(&deleted_reference), false);
        // assert_ne!(original_reference, deleted_reference);

        // // node.removePath(path2)
        // // const refDeleted = await node.save(saveFunction)
        // // // root reference should not remain the same
        // // expect(refDeleted).not.toStrictEqual(refOriginal)
        // // node.load(loadFunction, refDeleted)
        // // // 'm' key of prefix table disappeared
        // // const checkNode2 = getCheckNode()
        // // expect(Object.keys(checkNode2.forks)).toStrictEqual([String(path1[13])])
        // // // reference should differ because the changed fork set
        // // const refCheckNode2 = checkNode2.getContentAddress
        // // expect(refCheckNode2).not.toStrictEqual(refCheckNode1)
        // eprintln!("Manifest root: {:?}", hex::encode(node.content_address));
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::Rng;

    pub fn get_sample_mantaray_node() -> (MantarayNode, Vec<Vec<u8>>) {
        let rand_address = rand::thread_rng().gen::<[u8; 32]>();

        let mut node = MantarayNode {
            node_type: 0,
            obfuscation_key: ZERO_BYTES,
            cac: [].to_vec(),
            entry: rand_address.as_slice().to_vec(),
            metadata: HashMap::new(),
            forks: HashMap::new(),
        };

        let path1 = "path1/valami/elso";
        let path2 = "path1/valami/masodik";
        let path3 = "path1/valami/masodik.ext";
        let path4 = "path1/valami";
        let path5 = "path2";

        let mut path1_metadata = HashMap::<String, String>::new();
        path1_metadata.insert("vmi".to_string(), "elso".to_string());
        node.add_fork(path1.as_bytes(), &rand_address, path1_metadata);
        node.add_fork(
            path2.as_bytes(),
            &rand_address,
            HashMap::<String, String>::new(),
        );
        node.add_fork(
            path3.as_bytes(),
            &rand_address,
            HashMap::<String, String>::new(),
        );
        let mut path4_metadata = HashMap::<String, String>::new();
        path4_metadata.insert("vmi".to_string(), "negy".to_string());
        node.add_fork(path4.as_bytes(), &rand_address, path4_metadata);
        node.add_fork(
            path5.as_bytes(),
            &rand_address,
            HashMap::<String, String>::new(),
        );

        (
            node,
            vec![
                path1.as_bytes().to_vec(),
                path2.as_bytes().to_vec(),
                path3.as_bytes().to_vec(),
                path4.as_bytes().to_vec(),
                path5.as_bytes().to_vec(),
            ],
        )
    }

    #[test]
    fn serde() {
        let rand_address = rand::thread_rng().gen::<[u8; 32]>();
        let node = MantarayNode {
            node_type: 0,
            obfuscation_key: ZERO_BYTES,
            cac: [].to_vec(),
            entry: rand_address.as_slice().to_vec(),
            metadata: HashMap::new(),
            forks: HashMap::new(),
        };

        let serialised = node.serialize();
        eprintln!("{:x?}", serialised);

        let node_compare = MantarayNode::deserialize(&mut serialised.unwrap());

        assert_eq!(node.entry, node_compare.unwrap().entry);

        let (node, _) = get_sample_mantaray_node();

        let serialised = node.serialize();

        let node_compare = MantarayNode::deserialize(&mut serialised.unwrap());

        assert_eq!(node.entry, node_compare.unwrap().entry);
    }

    #[test]
    fn node_structure_check() {
        let (node, paths) = get_sample_mantaray_node();

        assert_eq!(
            node.forks.keys().cloned().collect::<Vec<u8>>(),
            vec![paths[0][0]]
        );
        let second_level_fork = node.forks.get(&paths[4][0]).unwrap();
        assert_eq!(second_level_fork.prefix, "path".as_bytes());
        let second_level_node = &second_level_fork.node;
        let mut second_level_node_keys =
            second_level_node.forks.keys().cloned().collect::<Vec<u8>>();
        second_level_node_keys.sort();
        assert_eq!(second_level_node_keys, vec![paths[0][4], paths[4][4]]);
        let third_level_fork_2 = second_level_node.forks.get(&paths[4][4]).unwrap();
        assert_eq!(third_level_fork_2.prefix, vec![paths[4][4]]);
        let third_level_fork_1 = second_level_node.forks.get(&paths[0][4]).unwrap();
        assert_eq!(third_level_fork_1.prefix, Vec::from("1/valami".as_bytes()));
        let third_level_node_1 = &third_level_fork_1.node;
        let mut third_level_node_keys = third_level_node_1
            .forks
            .keys()
            .cloned()
            .collect::<Vec<u8>>();
        third_level_node_keys.sort();
        assert_eq!(third_level_node_keys, vec![paths[0][12]]);
        let fourth_level_fork_1 = third_level_node_1.forks.get(&paths[0][12]).unwrap();
        assert_eq!(fourth_level_fork_1.prefix, vec![paths[0][12]]);
        let fourth_level_node_1 = &fourth_level_fork_1.node;
        let mut fourth_level_node_keys = fourth_level_node_1
            .forks
            .keys()
            .cloned()
            .collect::<Vec<u8>>();
        fourth_level_node_keys.sort();
        assert_eq!(fourth_level_node_keys, vec![paths[0][13], paths[1][13]]);
        let fifth_level_fork_2 = fourth_level_node_1.forks.get(&paths[1][13]).unwrap();
        assert_eq!(fifth_level_fork_2.prefix, Vec::from("masodik".as_bytes()));
        let fifth_level_node_2 = &fifth_level_fork_2.node;
        let mut fifth_level_node_keys = fifth_level_node_2
            .forks
            .keys()
            .cloned()
            .collect::<Vec<u8>>();
        fifth_level_node_keys.sort();
        assert_eq!(fifth_level_node_keys, vec![paths[2][20]]);
        let sixth_level_node_1 = fifth_level_node_2.forks.get(&paths[2][20]).unwrap();
        assert_eq!(sixth_level_node_1.prefix, Vec::from(".ext".as_bytes()));
    }

    #[test]
    #[should_panic(
        expected = "Path has not been found in the manifest. Remaining path on lookup: /not/exists"
    )]
    fn get_fork_at_path_panic() {
        let (node, _) = get_sample_mantaray_node();
        node.get_fork_at_path("path/not/exists".as_bytes());
    }

    #[test]
    fn get_fork_at_path() {
        let (node, paths) = get_sample_mantaray_node();

        // no separator in the descendants
        let fork1 = node.get_fork_at_path(String::from("path1/valami/").as_bytes());
        assert_eq!(MantarayNode::check_for_separator(&fork1.node), false);

        // separator in the descendants
        let fork2 = node.get_fork_at_path(&paths[3]);
        assert_eq!(MantarayNode::check_for_separator(&fork2.node), true);

        // no separator in the descendants, no forks
        let fork3 = node.get_fork_at_path(&paths[4]);
        assert_eq!(MantarayNode::check_for_separator(&fork3.node), false);
    }

    #[test]
    #[should_panic(expected = "Path has not been found in the manifest")]
    fn remove_path_panic() {
        let (mut node, _) = get_sample_mantaray_node();
        node.remove_path(vec![0, 1, 2]);
    }

    #[test]
    fn remove_path() {
        let (mut node, paths) = get_sample_mantaray_node();
        let check_node_1 = node
            .get_fork_at_path(&Vec::from("path1/valami/".as_bytes()))
            .node
            .clone();

        // current forks of node
        let mut check_node_keys = check_node_1.forks.keys().cloned().collect::<Vec<u8>>();
        check_node_keys.sort();
        assert_eq!(check_node_keys, vec![paths[0][13], paths[1][13]]);

        node.remove_path(paths[1][..].to_vec());
        let check_node_1 = node
            .get_fork_at_path(&Vec::from("path1/valami/".as_bytes()))
            .node
            .clone();
        // 'm' key of prefix table disappeared
        let check_node_keys = check_node_1.forks.keys().cloned().collect::<Vec<u8>>();

        assert_eq!(check_node_keys, vec![paths[0][13]]);
    }
}
