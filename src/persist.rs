use async_recursion::async_recursion;
use async_trait::async_trait;
use reqwest::blocking;
use std::fmt;
use std::sync::Mutex;
use std::{collections::HashMap, error::Error};

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
#[async_trait]
pub trait Loader {
    async fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

// saver defines a trait that stores nodes by reference to a storage backend.

#[async_trait]
pub trait Saver {
    async fn save(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

#[async_trait]
pub trait LoaderSaver: Sync {
    async fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
    async fn save(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
    async fn as_dyn(&self) -> &dyn LoaderSaver;
}

impl Node {
    // a load function for nodes
    pub async fn load<T: LoaderSaver + ?Sized>(&mut self, l: &Option<&T>) -> Result<(), Box<dyn Error>> {
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
        let mut data = l.unwrap().load(&ref_).await?;

        // unmarshall the node from dta into self
        self.unmarshal_binary(&mut data)?;

        // return success
        Ok(())
    }

    // save persists a trie recursively traversing the nodes
    pub async fn save<T: LoaderSaver + ?Sized + std::marker::Sync>(&mut self, s: &Option<&T>) -> Result<(), Box<dyn Error>> {
        self.save_recursive(s).await
    }

    #[async_recursion]
    pub async fn save_recursive<T: LoaderSaver + ?Sized + std::marker::Sync>(
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
            fork.node.save_recursive(s).await?;
        }

        // marshal the node to a slice of bytes
        let slice = self.marshal_binary()?;

        // save the node to the storage backend
        self.ref_ = s.as_ref().unwrap().save(&slice).await?;

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

#[async_trait]
impl LoaderSaver for MockLoadSaver {

    async fn as_dyn(&self) -> &dyn LoaderSaver {
        self
    }

    async fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let store = self.store.lock().unwrap();
        let data = store.get(ref_).unwrap();
        Ok(data.clone())
    }

    async fn save(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut store = self.store.lock().unwrap();
        let ref_ = keccak256(data);
        store.insert(ref_, data.to_vec());
        Ok(ref_.to_vec())
    }
}

pub struct BeeLoadSaver {
    uri: String,
    client: blocking::Client,
    stamp: Option<Vec<u8>>,
}

impl BeeLoadSaver {
    pub fn new(uri: String, stamp: Option<Vec<u8>>) -> BeeLoadSaver {
        BeeLoadSaver {
            uri,
            client: blocking::Client::new(),
            stamp,
        }
    }
}

#[async_trait]
impl LoaderSaver for BeeLoadSaver {
    async fn as_dyn(&self) -> &dyn LoaderSaver {
        self
    }

    async fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let url = format!("{}/bytes/{}", self.uri, hex::encode(ref_));
        let res = self.client.get(&url).send()?;

        // bubble up if there is an error
        if !res.status().is_success() {
            Err(Box::new(res.error_for_status().unwrap_err()))
        } else {
            let data = res.bytes()?;
            Ok(data.to_vec())
        }
    }

    async fn save(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        todo!();
        // let url = format!("{}/bytes", self.uri);
        // let res = self.client.post(&url).body(data).send()?;
        // let data: String = res.json::<serde_json::Value>()?;
        // Ok(data.to_vec())
    }
}
