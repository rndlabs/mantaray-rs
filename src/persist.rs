use std::fmt;
use std::{collections::HashMap, error::Error};
use std::sync::Mutex;
use reqwest::blocking;

use crate::{keccak256, marshal::Marshal, node::Node};

#[derive(Debug, Clone)]
struct NoLoaderError;
impl fmt::Display for NoLoaderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "No loader provided")
    }
}
impl Error for NoLoaderError {}

// loader defines a trait that retrieves nodes by reference from a storage backend.
pub trait Loader {
    fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

// saver defines a trait that stores nodes by reference to a storage backend.
pub trait Saver {
    fn save(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

pub trait LoaderSaver {
    fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
    fn save(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
    fn as_dyn(&self) -> &dyn LoaderSaver;
}

impl Node {
    // a load function for nodes
    pub fn load<T: LoaderSaver + ?Sized>(&mut self, l: &Option<&T>) -> Result<(), Box<dyn Error>> {
        // if ref_ is not a reference, return Ok
        if self.ref_.is_empty() {
            return Ok(());
        }

        // if l is not a loader, return no loader error
        if l.is_none() {
            return Err(Box::new(NoLoaderError));
        }

        // load the node from the storage backend
        let ref_ = self.ref_.clone();
        let mut data = l.as_ref().unwrap().load(&ref_)?;

        // unmarshall the node from dta into self
        self.unmarshal_binary(&mut data)?;

        // return success
        Ok(())
    }

    // save persists a trie recursively traversing the nodes
    pub fn save<T: LoaderSaver + ?Sized>(&mut self, s: &Option<&T>) -> Result<(), Box<dyn Error>> {
        self.save_recursive(s)
    }

    pub fn save_recursive<T: LoaderSaver + ?Sized>(
        &mut self,
        s: &Option<&T>,
    ) -> Result<(), Box<dyn Error>> {
        // if ref_ is already a reference, return
        if !self.ref_.is_empty() {
            return Ok(());
        }

        // recurse through the fork values of the node and save them
        // TODO! This is the area in which we can optimize the saving process.
        for fork in self.forks.values_mut() {
            fork.node.save_recursive(s)?;
        }

        // marshal the node to a slice of bytes
        let slice = self.marshal_binary()?;

        // save the node to the storage backend
        self.ref_ = s.as_ref().unwrap().save(&slice)?;

        self.forks.clear();

        Ok(())
    }
}

pub type Address = [u8; 32];

#[derive(Debug, Default)]
pub struct MockLoadSaver {
    store: Mutex<HashMap<Address, Vec<u8>>>,
}

impl MockLoadSaver {
    pub fn new() -> MockLoadSaver {
        MockLoadSaver {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl LoaderSaver for MockLoadSaver {
    fn as_dyn(&self) -> &dyn LoaderSaver {
        self
    }

    fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let store = self.store.lock().unwrap();
        let data = store.get(ref_).unwrap();
        Ok(data.clone())
    }

    fn save(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut store = self.store.lock().unwrap();
        let ref_ = keccak256(data);
        store.insert(ref_, data.to_vec());
        Ok(ref_.to_vec())
    }
}

pub struct BeeLoadSaver {
    uri: String,
    client: reqwest::Client,
    stamp: Option<Vec<u8>>,
}

impl BeeLoadSaver {
    pub fn new(uri: String, stamp: Option<Vec<u8>>) -> BeeLoadSaver {
        BeeLoadSaver {
            uri,
            client: reqwest::Client::new(),
            stamp,
        }
    }
}

impl LoadSaver for BeeLoadSaver {
    fn as_dyn(&self) -> &dyn LoaderSaver {
        self
    }

    fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let url = format!("{}/bytes/{}", self.uri, hex::encode(ref_));
        let res = self.client.get(&url).send()?;

        // bubble up if there is an error
        if !res.status().is_success() {
            return Err(Box::new(res.error_for_status().unwrap_err()));
        } else {
            let data = res.bytes()?;
            return Ok(data.to_vec());
        }
    }

    fn save(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        not_implemented!();
        let url = format!("{}/bytes", self.uri);
        let res = self.client.post(&url).body(data).send()?;
        let data: String = res.json::<serde_json::Value>()?;
        Ok(data.to_vec())
    }
}