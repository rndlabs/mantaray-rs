use std::collections::HashMap;
use std::sync::Mutex;

use crate::{keccak256, marshal::Marshal, node::Node};

// loader defines a trait that retrieves nodes by reference from a storage backend.
pub trait Loader {
    fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, String>;
}

// saver defines a trait that stores nodes by reference to a storage backend.
pub trait Saver {
    fn save(&self, data: &[u8]) -> Result<Vec<u8>, String>;
}

pub trait LoaderSaver {
    fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, String>;
    fn save(&self, data: &[u8]) -> Result<Vec<u8>, String>;
    fn as_dyn(&self) -> &dyn LoaderSaver;
}

impl Node {
    // a load function for nodes
    pub fn load<T: LoaderSaver + ?Sized>(&mut self, l: &Option<&T>) -> Result<(), String> {
        // if ref_ is not a reference, return Ok
        if self.ref_.is_empty() {
            return Ok(());
        }

        // if l is not a loader, return no loader error
        if l.is_none() {
            return Err("No loader".to_string());
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
    pub fn save<T: LoaderSaver + ?Sized>(&mut self, s: &Option<&T>) -> Result<(), String> {
        self.save_recursive(s)
    }

    pub fn save_recursive<T: LoaderSaver + ?Sized>(
        &mut self,
        s: &Option<&T>,
    ) -> Result<(), String> {
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

    fn load(&self, ref_: &[u8]) -> Result<Vec<u8>, String> {
        let store = self.store.lock().unwrap();
        let data = store.get(ref_).unwrap();
        Ok(data.clone())
    }

    fn save(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut store = self.store.lock().unwrap();
        let ref_ = keccak256(data);
        store.insert(ref_, data.to_vec());
        Ok(ref_.to_vec())
    }
}
