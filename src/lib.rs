use std::{collections::HashMap, error::Error};

use node::Node;
use persist::LoaderSaver;
use tiny_keccak::{Hasher, Keccak};

pub mod marshal;
pub mod node;
pub mod persist;

const PATH_SEPARATOR: &str = "/";

// node header field constraints
const NODE_OBFUSCATION_KEY_SIZE: usize = 32;
const VERSION_HASH_SIZE: usize = 31;
const NODE_REF_BYTES_SIZE: usize = 1;

// NODE_HEADER_SIZE defines the total size of the header part
const NODE_HEADER_SIZE: usize = NODE_OBFUSCATION_KEY_SIZE + VERSION_HASH_SIZE + NODE_REF_BYTES_SIZE;

// node fork constraints
const NODE_FORK_TYPE_BYTES_SIZE: usize = 1;
const NODE_FORK_PREFIX_BYTES_SIZE: usize = 1;
const NODE_FORK_HEADER_SIZE: usize = NODE_FORK_TYPE_BYTES_SIZE + NODE_FORK_PREFIX_BYTES_SIZE;
const NODE_FORK_PRE_REFERENCE_SIZE: usize = 32;
const NODE_PREFIX_MAX_SIZE: usize = NODE_FORK_PRE_REFERENCE_SIZE - NODE_FORK_HEADER_SIZE;
const NODE_FORK_METADATA_BYTES_SIZE: usize = 2;

const NT_VALUE: u8 = 2;
const NT_EDGE: u8 = 4;
const NT_WITH_PATH_SEPARATOR: u8 = 8;
const NT_WITH_METADATA: u8 = 16;
const NT_MASK: u8 = 255;

#[derive(Debug, Clone)]
struct NotValueTypeError;
impl std::fmt::Display for NotValueTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Not a value type")
    }
}
impl Error for NotValueTypeError {}

pub struct Manifest<'a, T: LoaderSaver + ?Sized + std::marker::Sync> {
    pub trie: Node,
    ls: Option<&'a T>,
}

impl<T: LoaderSaver + ?Sized + std::marker::Sync> Manifest<'_, T> {
    // new manataray manifest creates a new mantaray-based manifest.
    pub fn new(ls: Option<&T>, encrypted: bool) -> Manifest<T> {
        let mut mm = Manifest {
            ls,
            trie: Node::default(),
        };

        // use emtpy obfuscation key if encryption is not enabled
        if !encrypted {
            mm.trie.obfuscation_key = [0u8; NODE_OBFUSCATION_KEY_SIZE].to_vec();
        }

        mm
    }

    // new_manifest_reference loads existing mantaray-based manifest.
    pub fn new_manifest_reference<'a>(
        reference: Reference<'a>,
        ls: Option<&'a T>,
    ) -> Result<Manifest<'a, T>, String> {
        let mm = Manifest {
            ls,
            trie: Node::new_node_ref(reference),
        };

        Ok(mm)
    }

    // add a path and entry to the manifest.
    pub async fn add(&mut self, path: &str, entry: &Entry<'_>) -> Result<(), Box<dyn Error>> {
        self.trie
            .add(
                path.as_bytes(),
                entry.reference,
                entry.metadata.clone(),
                &self.ls,
            )
            .await
    }

    // remove a path from the manifest.
    pub async fn remove(&mut self, path: &str) -> Result<(), Box<dyn Error>> {
        self.trie.remove(path.as_bytes(), &self.ls).await
    }

    // lookup a path in the manifest.
    pub async fn lookup(&mut self, path: &str) -> Result<Entry, Box<dyn Error>> {
        let n = self.trie.lookup_node(path.as_bytes(), &self.ls).await?;

        // if the node is not a value type, return not found.
        if !n.is_value_type() {
            return Err(Box::new(NotValueTypeError {}));
        }

        // copy the metadata from the node.
        let metadata = n.metadata.clone();

        Ok(Entry {
            reference: &n.ref_,
            metadata,
        })
    }

    // determine if the manifest has a specified prefix.
    pub async fn has_prefix(&mut self, prefix: &str) -> Result<bool, Box<dyn Error>> {
        self.trie.has_prefix(prefix.as_bytes(), &self.ls).await
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
