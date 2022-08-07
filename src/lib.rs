pub mod marshal;
pub mod node;

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
