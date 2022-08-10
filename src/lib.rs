use std::collections::HashMap;

use node::Node;
use persist::{LoadSaver, Loader};
use tiny_keccak::{Keccak, Hasher};

pub mod marshal;
pub mod node;
pub mod persist;

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

// trait Loader {
//     fn load(&self, slice: &[u8]) -> Result<Vec<u8>, String>;
// }

// trait Saver {
//     fn save(&self, slice: &[u8]) -> Result<Vec<u8>, String>;
// }

pub struct Manifest {
    trie: Node,
    ls: Option<LoadSaver>
}

impl Manifest {
    // new manataray manifest creates a new mantaray-based manifest.
    pub fn new(ls: Option<LoadSaver>, encrypted: bool) -> Manifest{
        let mut mm = Manifest {
            ls,
            trie: Node::default(),
        };

        // use emtpy obfuscation key if encryption is not enabled
        if !encrypted {
            mm.trie.obfuscation_key = [0u8; NHS_OBFUSCATION_KEY].to_vec();
        }

        mm
    }

    // new_manifest_reference loads existing mantaray-based manifest.
    pub fn new_manifest_reference(reference: Reference, ls: Option<LoadSaver>) -> Result<Manifest, String> {
        let mm = Manifest {
            ls,
            trie: Node::new_node_ref(reference),
        };

        Ok(mm)
    }

    // add a path and entry to the manifest.
    pub fn add(&mut self, path: &str, entry: &Entry) -> Result<(), String> {
        self.trie.add(
            path.as_bytes(), 
            entry.reference, 
            entry.metadata.clone(),
            &self.ls
        )
    }

    // remove a path from the manifest.
    pub fn remove(&mut self, path: &str) -> Result<(), String> {
        self.trie.remove(path.as_bytes(), &self.ls)
    }

    // lookup a path in the manifest.
    pub fn lookup(&mut self, path: &str) -> Result<Entry, String> {
        let n = self.trie.lookup_node(path.as_bytes(), &self.ls)?;

        // if the node is not a value type, return not found.
        if !n.is_value_type() {
            return Err("not a value type".to_string());
        }

        // copy the metadata from the node.
        let metadata = n.metadata.clone();
        
        Ok(Entry {
            reference: &n.ref_,
            metadata,
        })
    }

    // determine if the manifest has a specified prefix.
    pub fn has_prefix(&mut self, prefix: &str) -> bool {
        self.trie.has_prefix(prefix.as_bytes(), &self.ls)
    }

    // todo!{"Finish manifest implementation"}

}

// define a trait that represents a single manifest entry.
pub struct Entry<'a> {
    reference: Reference<'a>,
    metadata: HashMap<String, String>,
}

type Reference<'a> = &'a [u8];

pub fn keccak256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes.as_ref());
    hasher.finalize(&mut output);
    output
}
