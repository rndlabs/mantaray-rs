use async_recursion::async_recursion;
use async_trait::async_trait;
use bee_api::BeeConfig;
use std::{fmt, error};
use std::sync::Mutex;
use std::{collections::HashMap, error::Error};

use crate::{keccak256, marshal::Marshal, node::Node};

type Result<T> = std::result::Result<T, Box<dyn error::Error + Send>>;

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
    async fn load(&self, ref_: &[u8]) -> Result<Vec<u8>>;
}

// saver defines a trait that stores nodes by reference to a storage backend.

#[async_trait]
pub trait Saver {
    async fn save(&self, data: &[u8]) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait LoaderSaver: Sync {
    async fn load(&self, ref_: &[u8]) -> Result<Vec<u8>>;
    async fn save(&self, data: &[u8]) -> Result<Vec<u8>>;
    async fn as_dyn(&self) -> &dyn LoaderSaver;
}

impl Node {
    // a load function for nodes
    pub async fn load<T: LoaderSaver + ?Sized>(
        &mut self,
        l: &Option<&T>,
    ) -> Result<()> {
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
    pub async fn save<T: LoaderSaver + ?Sized + std::marker::Sync>(
        &mut self,
        s: &Option<&T>,
    ) -> Result<()> {
        self.save_recursive(s).await
    }

    #[async_recursion]
    pub async fn save_recursive<T: LoaderSaver + ?Sized + std::marker::Sync>(
        &mut self,
        s: &Option<&T>,
    ) -> Result<()> {
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

    async fn load(&self, ref_: &[u8]) -> Result<Vec<u8>> {
        let store = self.store.lock().unwrap();
        let data = store.get(ref_).unwrap();
        Ok(data.clone())
    }

    async fn save(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut store = self.store.lock().unwrap();
        let ref_ = keccak256(data);
        store.insert(ref_, data.to_vec());
        Ok(ref_.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct BeeLoadSaver {
    pub uri: String,
    pub config: BeeConfig,
    pub client: reqwest::Client,
}

impl BeeLoadSaver {
    pub fn new(uri: String, config: BeeConfig) -> BeeLoadSaver {
        BeeLoadSaver {
            uri,
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl LoaderSaver for BeeLoadSaver {
    async fn as_dyn(&self) -> &dyn LoaderSaver {
        self
    }

    async fn load(&self, ref_: &[u8]) -> Result<Vec<u8>> {
        Ok(
            bee_api::bytes_get(self.client.clone(), self.uri.clone(), hex::encode(ref_))
                .await?
                .0,
        )
    }

    async fn save(&self, data: &[u8]) -> Result<Vec<u8>> {
        match hex::decode(bee_api::bytes_post(
            self.client.clone(),
            self.uri.clone(),
            data.to_vec(),
            self.config
                .upload
                .as_ref()
                .expect("UploadConfig not specified"),
        )
        .await?.ref_) {
            Ok(ref_) => Ok(ref_),
            Err(e) => Err(Box::new(e)),
        }
    }
}
