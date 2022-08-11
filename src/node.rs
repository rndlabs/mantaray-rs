
use crate::{persist::LoaderSaver};
use std::collections::HashMap;

use serde::*;
use serde_with::serde_as;

use crate::{
    NODE_PREFIX_MAX_SIZE, NODE_OBFUSCATION_KEY_SIZE, NT_EDGE, NT_MASK, NT_VALUE, NT_WITH_METADATA,
    NT_WITH_PATH_SEPARATOR, PATH_SEPARATOR,
};

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Node {
    pub node_type: u8,
    pub ref_bytes_size: u32,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub obfuscation_key: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub ref_: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub entry: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub forks: HashMap<u8, Fork>,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Fork {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub prefix: Vec<u8>,
    pub node: Node,
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

impl Node {
    pub fn new_node_ref(ref_: &[u8]) -> Node {
        Node {
            ref_: ref_.to_vec(),
            ..Default::default()
        }
    }

    // node type related functions

    // IsValueType returns true if the node contains entry.
    pub fn is_value_type(&self) -> bool {
        (self.node_type & NT_VALUE) == NT_VALUE
    }

    // IsEdgeType returns true if the node forks into other nodes.
    pub fn is_edge_type(&self) -> bool {
        (self.node_type & NT_EDGE) == NT_EDGE
    }

    // IsWithPathSeparatorType returns true if the node path contains separator character.
    pub fn is_with_path_separator_type(&self) -> bool {
        (self.node_type & NT_WITH_PATH_SEPARATOR) == NT_WITH_PATH_SEPARATOR
    }

    // IsWithMetadataType returns true if the node contains metadata.
    pub fn is_with_metadata_type(&self) -> bool {
        (self.node_type & NT_WITH_METADATA) == NT_WITH_METADATA
    }

    fn make_value(&mut self) {
        self.node_type |= NT_VALUE
    }

    pub fn make_edge(&mut self) {
        self.node_type |= NT_EDGE
    }

    fn make_with_path_separator(&mut self) {
        self.node_type |= NT_WITH_PATH_SEPARATOR
    }

    fn make_with_metadata(&mut self) {
        self.node_type |= NT_WITH_METADATA
    }

    // fn make_not_value(&mut self) {
    //     self.node_type &= NT_MASK ^ NT_VALUE
    // }

    // fn make_not_edge(&mut self) {
    //     self.node_type &= NT_MASK ^ NT_EDGE
    // }

    fn make_not_with_path_separator(&mut self) {
        self.node_type &= NT_MASK ^ NT_WITH_PATH_SEPARATOR
    }

    // fn make_not_with_metadata(&mut self) {
    //     self.node_type &= NT_MASK ^ NT_WITH_METADATA
    // }

    fn set_obfuscation_key(&mut self, key: &[u8]) {
        if key.len() != NODE_OBFUSCATION_KEY_SIZE {
            panic!("Invalid key length");
        }

        self.obfuscation_key = key.to_vec();
    }

    // lookupnode finds the node for a path or returns error if not found.
    pub fn lookup_node<T: LoaderSaver + ?Sized>(&mut self, path: &[u8], l: &Option<&T>) -> Result<&Node, String> {
        // if forks hashmap is empty, perhaps we haven't loaded the forks yet
        if self.forks.is_empty() {
            self.load(l)?;
        }

        // if the path is empty return the current node
        if path.is_empty() {
            return Ok(self);
        }

        match self.forks.get_mut(&path[0]) {
            None => Err(format!("No fork found for node: {:?}", self.ref_)),
            Some(f) => {
                // get the common prefix of the fork and the path
                let c = common(&f.prefix, path);

                // if c is the same length as the fork prefix then recursive lookup node
                if c.len() == f.prefix.len() {
                    f.node.lookup_node(&path[c.len()..], l)
                } else {
                    Err(format!("No fork found for node: {:?}", self.ref_))
                }
            }
        }
    }

    // lookup finds the entry for a path or returns error if not found
    pub fn lookup<T: LoaderSaver + ?Sized>(&mut self, path: &[u8], l: &Option<&T>) -> Result<&[u8], String> {
        let node = self.lookup_node(path, l)?;
        // if node is not value type and path lengther is greater than 0 return error
        if !node.is_value_type() && !path.is_empty() {
            return Err(format!("No entry found for node: {:?}", node.ref_));
        }

        Ok(node.entry.as_slice())
    }

    // Add adds an entry to the path with metadata
    pub fn add<T: LoaderSaver + ?Sized>(
        &mut self,
        path: &[u8],
        entry: &[u8],
        metadata: HashMap<String, String>,
        ls: &Option<&T>
    ) -> Result<(), String> {
        if self.ref_bytes_size == 0 {
            if entry.len() > 256 {
                return Err("node entry size > 256 bytes".to_string());
            }
            // empty entry for directories
            if !entry.is_empty() {
                self.ref_bytes_size = entry.len() as u32;
            }
        } else if !entry.is_empty() && entry.len() != self.ref_bytes_size as usize {
            return Err(format!(
                "node entry size: {:?} expected: {:?}",
                entry.len(),
                self.ref_bytes_size
            ));
        }

        // if path is empty then set entry and return
        if path.is_empty() {
            self.entry = entry.to_vec();
            self.make_value();

            // if metadata is not empty then set metadata and type flag then return
            if !metadata.is_empty() {
                self.metadata = metadata;
                self.make_with_metadata();
            }

            // set self ref to empty vec
            self.ref_ = vec![];
            return Ok(());
        }

        // if forks hashmap is empty, perhaps we haven't loaded the forks yet
        if self.forks.is_empty() {
            self.load(ls)?;
        }

        // try get the fork at the first character of the path
        let mut f = self.forks.get_mut(&path[0]);
        if f.is_none() {
            // create a new node
            let mut nn = Node::default();

            // if an obfuscation key is set then set it to the new node
            if !self.obfuscation_key.is_empty() {
                nn.set_obfuscation_key(&self.obfuscation_key);
            }

            nn.ref_bytes_size = self.ref_bytes_size;

            // check the prefix size limit
            if path.len() > NODE_PREFIX_MAX_SIZE {
                // split the path into two parts
                let (prefix, rest) = path.split_at(NODE_PREFIX_MAX_SIZE);

                // add rest to the new node
                nn.add(rest, entry, metadata, ls)?;
                nn.update_is_with_path_separator(prefix);

                // add the new node to the forks hashmap
                self.forks.insert(
                    path[0],
                    Fork {
                        prefix: prefix.to_vec(),
                        node: nn,
                    },
                );
                self.make_edge();

                // return
                return Ok(());
            }

            nn.entry = entry.to_vec();

            // if metadata is not empty then set metadata and type flag
            if !metadata.is_empty() {
                nn.metadata = metadata;
                nn.make_with_metadata();
            }

            nn.make_value();
            nn.update_is_with_path_separator(path);
            self.forks.insert(
                path[0],
                Fork {
                    prefix: path.to_vec(),
                    node: nn,
                },
            );
            self.make_edge();
            return Ok(());
        }

        // get the common prefix of the fork and the path, then get the rest of the path
        let c = common(&f.as_ref().unwrap().prefix, path);
        let rest = f.as_ref().unwrap().prefix[c.len()..].to_vec();

        // get mutable reference to the fork node
        let mut nn = f.as_ref().unwrap().node.clone();

        // if the rest of the path is not empty move current common prefix node
        if !rest.is_empty() {
            // move current common prefix ndoe
            nn = Node::default();

            // if an obfuscation key is set then set it to the new node
            if !self.obfuscation_key.is_empty() {
                nn.set_obfuscation_key(&self.obfuscation_key);
            }

            nn.ref_bytes_size = self.ref_bytes_size;

            // update the fork node with the rest of the path
            f.as_mut()
                .unwrap()
                .node
                .update_is_with_path_separator(&rest);

            // add the fork node to the new node forks hashmap
            nn.forks.insert(
                rest[0],
                Fork {
                    prefix: rest.to_vec(),
                    node: f.unwrap().node.clone(),
                },
            );
            nn.make_edge();

            // if common path is full path new node is value type
            if c.len() == path.len() {
                nn.make_value();
            }
        }
        // note: special case on edge split
        nn.update_is_with_path_separator(path);

        // add new node for shared prefix
        nn.add(&path[c.len()..], entry, metadata, ls)?;

        // add the new node to the forks hashmap
        self.forks.insert(
            path[0],
            Fork {
                prefix: c.to_vec(),
                node: nn,
            },
        );
        self.make_edge();

        // return
        Ok(())
    }

    fn update_is_with_path_separator(&mut self, path: &[u8]) {
        // if path conatins a path separator at an index greater than 0 then set is_with_path_separator flag
        for i in path.iter().skip(1) {
            if *i == PATH_SEPARATOR.as_bytes()[0] {
                self.make_with_path_separator();
                return;
            }
        }

        self.make_not_with_path_separator();
    }

    // remove removes a path from the node
    pub fn remove<T: LoaderSaver + ?Sized>(&mut self, path: &[u8], ls: &Option<&T>) -> Result<(), String> {
        // if path is empty then return error
        if path.is_empty() {
            return Err("path is empty".to_string());
        }

        // if forks is empty then load
        if self.forks.is_empty() {
            self.load(ls)?;
        }

        // if path is not empty then get the fork at the first character of the path
        let f = self.forks.get_mut(&path[0]);
        if f.is_none() {
            return Err("No entry found for node".to_string());
        }

        // returns the index of the first instance of sep in s, or -1 if sep is not present in s.
        let prefix_index = find_index_of_array(path, &f.as_ref().unwrap().prefix);
        if prefix_index.is_none() {
            return Err(format!("No entry found for path {:?}", path.to_vec()));
        }

        let rest = &path[f.as_ref().unwrap().prefix.len()..];
        if rest.is_empty() {
            // full path matched
            self.forks.remove(&path[0]);
            self.ref_ = vec![];
            return Ok(());
        }

        f.unwrap().node.remove(rest, ls)
    }

    // hasprefix tests whether the node contains prefix path
    pub fn has_prefix<T: LoaderSaver + ?Sized>(&mut self, path: &[u8], l: &Option<&T>) -> Result<bool, String> {
        // if path is empty then return false
        if path.is_empty() {
            return Ok(true);
        }

        // if forks is empty then load
        if self.forks.is_empty() {
            self.load(l)?;
        }

        // if path is not empty then get the fork at the first character of the path
        let fork = self.forks.get_mut(&path[0]);
        if fork.is_none() {
            return Ok(false);
        }

        // returns the index of the first instance of sep in s, or -1 if sep is not present in s.
        let c = common(&fork.as_ref().unwrap().prefix, path);

        // if common prefix is full path then return true
        if c.len() == fork.as_ref().unwrap().prefix.len() {
            return fork.unwrap().node.has_prefix(&path[c.len()..], l);
        }

        // determine if a fork prefix begins with the byte slice t.
        if fork.unwrap().prefix.starts_with(path) {
            return Ok(true);
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {

    use crate::persist::MockLoadSaver;

    use super::*;
    use rand::Rng;
    use test_case::test_case;

    struct TestCase<'a> {
        name: String,
        items: Vec<&'a str>,
    }

    #[test]
    fn nil_path() {
        let mut n = Node::default();
        assert_eq!(n.lookup::<dyn LoaderSaver>("".as_bytes(), &None).is_ok(), true);
    }

    // test data
    fn test_case_data() -> [TestCase<'static>; 6] {
        [
            TestCase {
                name: "a".to_string(),
                items: vec![
                    "aaaaaa", 
                    "aaaaab",
                    "abbbb",
                    "abbba",
                    "bbbbba",
                    "bbbaaa",
                    "bbbaab",
                    "aa",
                    "b"
                    ],
            },
            TestCase {
                name: "simple".to_string(),
                items: vec![
                    "/",
                    "index.html",
                    "img/1.png",
                    "img/2.png",
                    "robots.txt"
                    ],
            },
            TestCase {
                name: "nested-value-node-is-recognized".to_string(),
                items: vec![
                    "..............................@",
                    ".............................."
                    ],
            },
            TestCase {
                name: "nested-prefix-is-not-collapsed".to_string(),
                items: vec![
                    "index.html",
                    "img/1.png",
                    "img/2/test1.png",
                    "img/2/test2.png",
                    "robots.txt"
                    ],
            },
            TestCase {
                name: "conflicting-path".to_string(),
                items: vec![
                    "app.js.map",
                    "app.js"
                ],
            },
            TestCase {
                name: "spa-website".to_string(),
                items: vec![
                    "css/",
                    "css/app.css",
                    "favicon.ico",
                    "img/",
                    "img/logo.png",
                    "index.html",
                    "js/",
                    "js/chunk-vendors.js.map",
                    "js/chunk-vendors.js",
                    "js/app.js.map",
                    "js/app.js"
                ],
            }    
        ]
    }


    #[test]
    fn add_and_lookup() {
        let mut n = Node::default();
        for (i, c) in test_case_data()[0].items.iter().enumerate() {
            // create a vector from the string c zero padded to the left to 32 bytes
            let e = vec![0; 32 - c.len()].iter().chain(c.as_bytes().iter()).cloned().collect::<Vec<u8>>();
            assert_eq!(n.add::<dyn LoaderSaver>(c.as_bytes(), &e, HashMap::new(), &None), Ok(()));

            for j in 0..i {
                let d = test_case_data()[0].items[j].as_bytes();
                let m = n.lookup::<dyn LoaderSaver>(d, &None); 
                assert_eq!(m.is_ok(), true);
                let de = vec![0; 32 - d.len()].iter().chain(d.iter()).cloned().collect::<Vec<u8>>();
                assert_eq!(m.unwrap(), de);
            }            
        }
    }

    #[test_case(test_case_data()[0].items.clone() ; "a")]
    #[test_case(test_case_data()[1].items.clone() ; "simple")]
    #[test_case(test_case_data()[2].items.clone() ; "nested-value-node-is-recognized")]
    #[test_case(test_case_data()[3].items.clone() ; "nested-prefix-is-not-collapsed")]
    #[test_case(test_case_data()[4].items.clone() ; "conflicting-path")]
    #[test_case(test_case_data()[5].items.clone() ; "spa-website")]
    fn add_and_lookup_node(tc: Vec<&str>) {
        let mut n = Node::default();

        for (i, c) in tc.iter().enumerate() {
            // create a vector from the string c zero padded to the left to 32 bytes
            let e = vec![0; 32 - c.len()].iter().chain(c.as_bytes().iter()).cloned().collect::<Vec<u8>>();
            assert_eq!(n.add::<dyn LoaderSaver>(c.as_bytes(), &e, HashMap::new(), &None), Ok(()));

            for j in 0..i {
                let d = tc[j];
                let node = n.lookup_node::<dyn LoaderSaver>(d.as_bytes(), &None).unwrap();
                assert_eq!(node.is_value_type(), true);
                let de = vec![0; 32 - d.len()].iter().chain(d.as_bytes().iter()).cloned().collect::<Vec<u8>>();
                assert_eq!(node.entry, de);
            }            
        }
    }

    #[test_case(test_case_data()[0].items.clone() ; "a")]
    #[test_case(test_case_data()[1].items.clone() ; "simple")]
    #[test_case(test_case_data()[2].items.clone() ; "nested-value-node-is-recognized")]
    #[test_case(test_case_data()[3].items.clone() ; "nested-prefix-is-not-collapsed")]
    #[test_case(test_case_data()[4].items.clone() ; "conflicting-path")]
    #[test_case(test_case_data()[5].items.clone() ; "spa-website")]
    fn add_and_lookup_node_with_load_save(tc: Vec<&str>) {
        let mut n = Node::default();

        for c in &tc {
            // create a vector from the string c zero padded to the left to 32 bytes
            let e = vec![0; 32 - c.len()].iter().chain(c.as_bytes().iter()).cloned().collect::<Vec<u8>>();
            assert_eq!(n.add::<dyn LoaderSaver>(c.as_bytes(), &e, HashMap::new(), &None), Ok(()));
        }

        let ls = MockLoadSaver::new();

        let save = n.save(&Some(&ls));
        assert_eq!(save.is_ok(), true);

        let mut n2 = Node::new_node_ref(&n.ref_);

        for d in tc {
            let node = n2.lookup_node(d.as_bytes(), &Some(&ls)).unwrap();
            assert_eq!(node.is_value_type(), true);
            let de = vec![0; 32 - d.len()].iter().chain(d.as_bytes().iter()).cloned().collect::<Vec<u8>>();
            assert_eq!(node.entry, de);
        }

    }

    pub fn get_sample_mantaray_node() -> Result<(Node, Vec<Vec<u8>>), String> {
        let rand_address = rand::thread_rng().gen::<[u8; 32]>();

        let mut node = Node {
            node_type: 0,
            obfuscation_key: [].to_vec(),
            ref_: [].to_vec(),
            entry: rand_address.as_slice().to_vec(),
            metadata: HashMap::new(),
            forks: HashMap::new(),
            ref_bytes_size: Default::default(),
        };

        let path1 = "path1/valami/elso";
        let path2 = "path1/valami/masodik";
        let path3 = "path1/valami/masodik.ext";
        let path4 = "path1/valami";
        let path5 = "path2";

        let ls = MockLoadSaver::new();

        let mut path1_metadata = HashMap::<String, String>::new();
        path1_metadata.insert("vmi".to_string(), "elso".to_string());
        node.add(path1.as_bytes(), &rand_address, path1_metadata, &Some(&ls))?;
        node.add(
            path2.as_bytes(),
            &rand_address,
            HashMap::<String, String>::default(),
            &Some(&ls)
        )?;
        node.add(
            path3.as_bytes(),
            &rand_address,
            HashMap::<String, String>::new(),
            &Some(&ls)
        )?;
        let mut path4_metadata = HashMap::<String, String>::new();
        path4_metadata.insert("vmi".to_string(), "negy".to_string());
        node.add(path4.as_bytes(), &rand_address, path4_metadata, &Some(&ls))?;
        node.add(
            path5.as_bytes(),
            &rand_address,
            HashMap::<String, String>::new(),
            &Some(&ls)
        )?;

        Ok((
            node,
            vec![
                path1.as_bytes().to_vec(),
                path2.as_bytes().to_vec(),
                path3.as_bytes().to_vec(),
                path4.as_bytes().to_vec(),
                path5.as_bytes().to_vec(),
            ],
        ))
    }

}


//     #[test]
//     fn node_structure_check() {
//         let (node, paths) = get_sample_mantaray_node().unwrap();

//         eprintln!(
//             "After save: {}",
//             serde_json::to_string_pretty(&node)
//                 .unwrap()
//                 .replace("\\", "")
//         );

//         assert_eq!(
//             node.forks.keys().cloned().collect::<Vec<u8>>(),
//             vec![paths[0][0]]
//         );
//         let second_level_fork = node.forks.get(&paths[4][0]).unwrap();
//         assert_eq!(second_level_fork.prefix, "path".as_bytes());
//         let second_level_node = &second_level_fork.node;
//         let mut second_level_node_keys =
//             second_level_node.forks.keys().cloned().collect::<Vec<u8>>();
//         second_level_node_keys.sort();
//         assert_eq!(second_level_node_keys, vec![paths[0][4], paths[4][4]]);
//         let third_level_fork_2 = second_level_node.forks.get(&paths[4][4]).unwrap();
//         assert_eq!(third_level_fork_2.prefix, vec![paths[4][4]]);
//         let third_level_fork_1 = second_level_node.forks.get(&paths[0][4]).unwrap();
//         assert_eq!(third_level_fork_1.prefix, Vec::from("1/valami".as_bytes()));
//         let third_level_node_1 = &third_level_fork_1.node;
//         let mut third_level_node_keys = third_level_node_1
//             .forks
//             .keys()
//             .cloned()
//             .collect::<Vec<u8>>();
//         third_level_node_keys.sort();
//         assert_eq!(third_level_node_keys, vec![paths[0][12]]);
//         let fourth_level_fork_1 = third_level_node_1.forks.get(&paths[0][12]).unwrap();
//         assert_eq!(fourth_level_fork_1.prefix, vec![paths[0][12]]);
//         let fourth_level_node_1 = &fourth_level_fork_1.node;
//         let mut fourth_level_node_keys = fourth_level_node_1
//             .forks
//             .keys()
//             .cloned()
//             .collect::<Vec<u8>>();
//         fourth_level_node_keys.sort();
//         assert_eq!(fourth_level_node_keys, vec![paths[0][13], paths[1][13]]);
//         let fifth_level_fork_2 = fourth_level_node_1.forks.get(&paths[1][13]).unwrap();
//         assert_eq!(fifth_level_fork_2.prefix, Vec::from("masodik".as_bytes()));
//         let fifth_level_node_2 = &fifth_level_fork_2.node;
//         let mut fifth_level_node_keys = fifth_level_node_2
//             .forks
//             .keys()
//             .cloned()
//             .collect::<Vec<u8>>();
//         fifth_level_node_keys.sort();
//         assert_eq!(fifth_level_node_keys, vec![paths[2][20]]);
//         let sixth_level_node_1 = fifth_level_node_2.forks.get(&paths[2][20]).unwrap();
//         assert_eq!(sixth_level_node_1.prefix, Vec::from(".ext".as_bytes()));
//     }

//     #[test]
//     fn get_fork_at_path_panic() {
//         let (node, _) = get_sample_mantaray_node().unwrap();
//         assert_eq!(
//             node.lookup_node("path/not/exists".as_bytes()).is_err(),
//             true
//         );
//     }

//     #[test]
//     fn get_fork_at_path() {
//         let (node, paths) = get_sample_mantaray_node().unwrap();

//         // no separator in the descendants
//         let fork1 = node
//             .lookup_node(String::from("path1/valami/").as_bytes())
//             .unwrap();
//         assert_eq!(check_for_separator(&fork1), false);

//         // separator in the descendants
//         let fork2 = node.lookup_node(&paths[3]).unwrap();
//         assert_eq!(check_for_separator(&fork2), true);

//         // no separator in the descendants, no forks
//         let fork3 = node.lookup_node(&paths[4]);
//         assert_eq!(fork3.is_ok(), false);
//     }

//     #[test]
//     fn remove_path_panic() {
//         let (mut node, _) = get_sample_mantaray_node().unwrap();
//         assert_eq!(node.remove("path/not/exists".as_bytes()).is_err(), true);
//     }

//     #[test]
//     fn remove_path() {
//         let (mut node, paths) = get_sample_mantaray_node().unwrap();
//         let check_node_1 = node
//             .lookup_node(&Vec::from("path1/valami/".as_bytes()))
//             .unwrap()
//             .clone();

//         // current forks of node
//         let mut check_node_keys = check_node_1.forks.keys().cloned().collect::<Vec<u8>>();
//         check_node_keys.sort();
//         assert_eq!(check_node_keys, vec![paths[0][13], paths[1][13]]);

//         node.remove(&paths[1][..]).unwrap();
//         let check_node_1 = node
//             .lookup_node(&Vec::from("path1/valami/".as_bytes()))
//             .unwrap()
//             .clone();
//         // 'm' key of prefix table disappeared
//         let check_node_keys = check_node_1.forks.keys().cloned().collect::<Vec<u8>>();

//         assert_eq!(check_node_keys, vec![paths[0][13]]);
//     }

//     fn check_for_separator(node: &Node) -> bool {
//         for fork in node.forks.values() {
//             if fork.prefix.iter().any(|&v| v == 47) || check_for_separator(&fork.node) {
//                 return true;
//             }
//         }

//         false
//     }
// }
