//! Path-based programmable virtual filesystem.
//!
//! `VirtualFs<P>` is a [`DynFileSystem`] scaffold that owns every FUSE-shaped
//! concern — inode allocation, the inode↔path map, open-handle tables, lookup
//! reference counting, `stat64`/`Entry` construction, readdir cookie paging,
//! and zero-copy I/O — and delegates the *semantics* of each operation to a
//! user-supplied [`PathFs`] provider keyed by absolute guest path.
//!
//! This realizes the "filesystem as a UI layer for the agent" pattern: a
//! provider maps `read`/`readdir`/`write`/`create`/`rename`/… directly onto a
//! backend (an in-memory map, a database, an object store, a remote API),
//! while the scaffold handles all the kernel-facing bookkeeping.
//!
//! Like the sibling backends, the `DynFileSystem` trait impl here is thin: each
//! method delegates to a `do_*` method grouped by concern into a sibling module
//! (`metadata`, `dir_ops`, `file_ops`, `create_ops`, `remove_ops`,
//! `xattr_ops`), with the shared inode/handle bookkeeping in `inode`.
//!
//! ## Scope
//!
//! `VirtualFs` is keyed purely by path, so **hard links are not supported** (a
//! path API cannot express two names sharing one inode). It is meant for
//! mounting data sources as a subtree, not as a bootable rootfs.

mod config;
mod create_ops;
mod dir_ops;
mod file_ops;
mod inode;
mod metadata;
mod path_fs;
mod remove_ops;
pub mod rpc;
mod types;
mod xattr_ops;

#[cfg(test)]
mod test_backend;
#[cfg(test)]
mod tests;

pub use config::{CachePolicy, VirtualFsConfig};
pub(crate) use inode::*;
#[cfg(unix)]
pub use path_fs::as_path;
pub use path_fs::{NodeKind, PathFs, VAttr, VDirEntry};

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io;
use std::sync::{Arc, RwLock, atomic::AtomicU64};
use std::time::Duration;

use types::{VDirHandle, VFileHandle, VNode};

use crate::backends::shared::{inode_table::MultikeyBTreeMap, platform};
use crate::{
    Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter, stat64, statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Root inode number (FUSE convention).
pub(crate) const ROOT_INODE: u64 = 1;

/// Guest Linux open flags. `VirtualFs` interprets these directly, so it must
/// use guest values on every host platform.
pub(crate) const GUEST_O_TRUNC: u32 = 0x200;

/// `SEEK_SET` — seek to an absolute offset.
pub(crate) const SEEK_SET: u32 = 0;

/// `SEEK_END` — seek relative to end-of-file.
pub(crate) const SEEK_END: u32 = 2;

/// `SEEK_DATA` — seek to next data region.
pub(crate) const SEEK_DATA: u32 = 3;

/// `SEEK_HOLE` — seek to next hole region.
pub(crate) const SEEK_HOLE: u32 = 4;

/// XATTR_CREATE flag (Linux value).
pub(crate) const XATTR_CREATE: u32 = 1;

/// XATTR_REPLACE flag (Linux value).
pub(crate) const XATTR_REPLACE: u32 = 2;

/// Linux `RENAME_NOREPLACE` flag.
pub(crate) const RENAME_NOREPLACE: u32 = 1;

/// Linux `RENAME_EXCHANGE` flag.
pub(crate) const RENAME_EXCHANGE: u32 = 2;

pub(crate) const KNOWN_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;

/// Maximum bytes per read/write (matches [`rpc::protocol::MAX_IO_SIZE`]).
pub(crate) const MAX_IO_SIZE: u32 = rpc::protocol::MAX_IO_SIZE;

/// Per-entry byte cost the guest kernel charges for one `readdir` dirent
/// (`fuse_dirent` is 24 bytes + name, 8-byte aligned; rounded up to 32 for
/// margin). Deliberately an *over*-estimate: the page we return must never
/// exceed the kernel's reply buffer, because the FUSE adapter silently drops
/// overflow entries — and `readdirplus` has already taken a lookup reference for
/// each, which the kernel would then never `FORGET`.
pub(crate) const FUSE_DIRENT_HEADER: usize = 32;

/// Per-entry byte cost for one `readdirplus` dirent (`fuse_direntplus` =
/// `fuse_entry_out` (128) + `fuse_dirent` (24) + name, 8-byte aligned; rounded
/// up to 160 for margin). See [`FUSE_DIRENT_HEADER`].
pub(crate) const FUSE_DIRENTPLUS_HEADER: usize = 160;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Path-based programmable virtual filesystem.
///
/// Construct with [`VirtualFs::new`] (default config) or
/// [`VirtualFs::with_config`], passing any [`PathFs`] provider.
pub struct VirtualFs<P: PathFs> {
    /// The semantic backend.
    pub(crate) provider: P,
    /// Inode table with both keys (inode → node and absolute path → inode) in
    /// one structure, so the two indexes can never disagree.
    pub(crate) inodes: RwLock<MultikeyBTreeMap<u64, Vec<u8>, Arc<VNode>>>,
    /// Open file handle table.
    pub(crate) file_handles: RwLock<BTreeMap<u64, Arc<VFileHandle>>>,
    /// Open directory handle table.
    pub(crate) dir_handles: RwLock<BTreeMap<u64, Arc<VDirHandle>>>,
    /// Next inode to allocate (1 = root).
    pub(crate) next_inode: AtomicU64,
    /// Next handle to allocate.
    pub(crate) next_handle: AtomicU64,
    /// Configuration.
    pub(crate) cfg: VirtualFsConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    /// Create a `VirtualFs` over `provider` with default configuration.
    pub fn new(provider: P) -> io::Result<Self> {
        Self::with_config(provider, VirtualFsConfig::default())
    }

    /// Create a `VirtualFs` over `provider` with the given configuration.
    pub fn with_config(provider: P, cfg: VirtualFsConfig) -> io::Result<Self> {
        let root = Arc::new(VNode {
            inode: ROOT_INODE,
            path: RwLock::new(b"/".to_vec()),
            // Pin the root so it is never evicted.
            lookup_refs: AtomicU64::new(u64::MAX / 2),
        });

        let mut inodes = MultikeyBTreeMap::new();
        inodes.insert(ROOT_INODE, b"/".to_vec(), root);

        Ok(Self {
            provider,
            inodes: RwLock::new(inodes),
            file_handles: RwLock::new(BTreeMap::new()),
            dir_handles: RwLock::new(BTreeMap::new()),
            next_inode: AtomicU64::new(ROOT_INODE + 1),
            next_handle: AtomicU64::new(1),
            cfg,
        })
    }

    /// Borrow the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> DynFileSystem for VirtualFs<P> {
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let mut opts = FsOptions::empty();
        let wanted = FsOptions::DONT_MASK
            | FsOptions::BIG_WRITES
            | FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::MAX_PAGES;
        opts |= capable & wanted;

        if capable.contains(FsOptions::DO_READDIRPLUS) {
            opts |= FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        }

        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
        }

        Ok(opts)
    }

    /// Tear down inode and handle tables. The FUSE session must be quiesced
    /// before this is called.
    fn destroy(&self) {
        self.file_handles.write().unwrap().clear();
        self.dir_handles.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(parent, name)
    }

    fn forget(&self, _ctx: Context, ino: u64, count: u64) {
        self.forget_one(ino, count);
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(u64, u64)>) {
        for (ino, count) in requests {
            self.forget_one(ino, count);
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        self.do_getattr(ino)
    }

    fn setattr(
        &self,
        _ctx: Context,
        ino: u64,
        attr: stat64,
        _handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        self.do_setattr(ino, attr, valid)
    }

    fn readlink(&self, _ctx: Context, ino: u64) -> io::Result<Vec<u8>> {
        self.do_readlink(ino)
    }

    fn symlink(
        &self,
        _ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_symlink(linkname, parent, name)
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_mknod(parent, name, mode, rdev, umask)
    }

    fn mkdir(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_mkdir(parent, name, mode, umask)
    }

    fn unlink(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name)
    }

    fn rmdir(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.do_rmdir(parent, name)
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.do_rename(olddir, oldname, newdir, newname, flags)
    }

    fn link(
        &self,
        _ctx: Context,
        _ino: u64,
        _newparent: u64,
        _newname: &CStr,
    ) -> io::Result<Entry> {
        // Hard links cannot be expressed by a path-keyed provider.
        Err(platform::enosys())
    }

    fn open(
        &self,
        _ctx: Context,
        ino: u64,
        _kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        self.do_open(ino, flags)
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        _kill_priv: bool,
        _flags: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        self.do_create(parent, name, mode, umask)
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _ctx: Context,
        _ino: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        self.do_read(handle, w, size, offset)
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _ctx: Context,
        _ino: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        self.do_write(handle, r, size, offset)
    }

    fn flush(&self, _ctx: Context, _ino: u64, handle: u64, _lock_owner: u64) -> io::Result<()> {
        self.do_flush(handle)
    }

    fn fsync(&self, _ctx: Context, _ino: u64, datasync: bool, handle: u64) -> io::Result<()> {
        self.do_fsync(handle, datasync)
    }

    fn fallocate(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        self.do_fallocate(ino, mode, offset, length)
    }

    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        _ctx: Context,
        _ino: u64,
        _flags: u32,
        handle: u64,
        flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.do_release(handle, flush)
    }

    fn statfs(&self, _ctx: Context, _ino: u64) -> io::Result<statvfs64> {
        self.provider.statfs()
    }

    fn setxattr(
        &self,
        _ctx: Context,
        ino: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.do_setxattr(ino, name, value, flags)
    }

    fn getxattr(
        &self,
        _ctx: Context,
        ino: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.do_getxattr(ino, name, size)
    }

    fn listxattr(&self, _ctx: Context, ino: u64, size: u32) -> io::Result<ListxattrReply> {
        self.do_listxattr(ino, size)
    }

    fn removexattr(&self, _ctx: Context, ino: u64, name: &CStr) -> io::Result<()> {
        self.do_removexattr(ino, name)
    }

    fn opendir(
        &self,
        _ctx: Context,
        ino: u64,
        _flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        self.do_opendir(ino)
    }

    fn readdir(
        &self,
        _ctx: Context,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        self.do_readdir(ino, handle, size, offset)
    }

    fn readdirplus(
        &self,
        _ctx: Context,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        self.do_readdirplus(ino, handle, size, offset)
    }

    fn fsyncdir(&self, _ctx: Context, ino: u64, _datasync: bool, handle: u64) -> io::Result<()> {
        self.do_fsyncdir(ino, handle)
    }

    fn releasedir(&self, _ctx: Context, _ino: u64, _flags: u32, handle: u64) -> io::Result<()> {
        self.do_releasedir(handle)
    }

    fn access(&self, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
        self.do_access(ctx, ino, mask)
    }

    fn lseek(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.do_lseek(ino, offset, whence)
    }
}
