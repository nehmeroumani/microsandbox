//! Internal types for the [`VirtualFs`](super::VirtualFs) scaffold: live inodes,
//! open handles, and directory snapshot entries.

use std::sync::{Arc, Mutex, RwLock, atomic::AtomicU64};

use crate::backends::shared::dir_snapshot::SnapshotEntry;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A live inode: the scaffold's record of a path that the guest is referencing.
pub(crate) struct VNode {
    /// FUSE inode number.
    pub(crate) inode: u64,
    /// Absolute guest path (mutated on rename). Begins with `/`.
    pub(crate) path: RwLock<Vec<u8>>,
    /// FUSE lookup reference count.
    pub(crate) lookup_refs: AtomicU64,
}

/// An open file handle.
pub(crate) struct VFileHandle {
    /// The node, kept alive for the handle's lifetime (survives unlink).
    pub(crate) node: Arc<VNode>,
    /// Guest path captured at open time for provider I/O after unlink.
    pub(crate) path: Vec<u8>,
}

/// An open directory handle.
pub(crate) struct VDirHandle {
    /// The node, kept alive for the handle's lifetime.
    pub(crate) node: Arc<VNode>,
    /// Entry snapshot, built lazily on first readdir.
    pub(crate) snapshot: Mutex<Option<Vec<VSnapEntry>>>,
}

/// A single entry in a directory snapshot.
pub(crate) struct VSnapEntry {
    pub(crate) name: Vec<u8>,
    pub(crate) inode: u64,
    pub(crate) offset: u64,
    pub(crate) file_type: u32,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SnapshotEntry for VSnapEntry {
    fn inode(&self) -> u64 {
        self.inode
    }
    fn offset(&self) -> u64 {
        self.offset
    }
    fn file_type(&self) -> u32 {
        self.file_type
    }
    fn name(&self) -> &[u8] {
        &self.name
    }
}
