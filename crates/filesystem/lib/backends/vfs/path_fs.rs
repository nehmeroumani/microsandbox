//! The [`PathFs`] provider trait and its portable supporting types.
//!
//! A [`PathFs`] implementation is the *semantic* half of a programmable
//! filesystem: it answers operations addressed by **absolute guest path**
//! (e.g. `read("/inbox/msg1.txt")`, `readdir("/inbox")`) and is free to back
//! them with anything — an in-memory map, a database, an object store, or a
//! remote API.
//!
//! The [`VirtualFs`](super::VirtualFs) scaffold owns everything FUSE-shaped —
//! inode allocation, the inode↔path map, open-handle tables, lookup
//! reference counting, `stat64`/`Entry` construction, readdir cookie paging,
//! and zero-copy plumbing — and translates each FUSE request into one of the
//! path-addressed calls below. Providers never see inodes or handles.
//!
//! ## Paths
//!
//! Every path is an absolute, `/`-separated, non-NUL **byte string** (`&[u8]`)
//! beginning with `/` — the same representation the RPC wire and the Go SDK's
//! `[]byte` use. Guest paths are Linux paths and need not be valid UTF-8, so
//! they are never `&Path`/`&str`; on unix hosts [`as_path`] converts a byte
//! path to a host `&Path` for providers that call into the host filesystem.
//!
//! ## Error reporting
//!
//! Every method returns [`io::Result`]. Errors propagate to the guest verbatim
//! as a **Linux** errno (the value the FUSE guest and the RPC wire speak), so
//! construct them with [`io::Error::from_raw_os_error`] using `libc::ENOENT`,
//! `libc::EACCES`, etc. On Linux those constants already are the wire values; on
//! a non-Linux dev host a provider that obtains an errno from a raw host syscall
//! must translate it to Linux first, since the runtime forwards it unchanged. A
//! plain [`io::Error`] without an OS code is surfaced to the guest as `EIO`.

use std::{io, time::SystemTime};

use crate::backends::shared::{name_validation, platform};
use crate::{SetattrValid, statvfs64};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The kind of a filesystem node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link.
    Symlink,
    /// Character device.
    Char,
    /// Block device.
    Block,
    /// Named pipe (FIFO).
    Fifo,
    /// Unix domain socket.
    Socket,
}

impl NodeKind {
    /// The `S_IF*` type bits for this kind, as a mode value (Linux values —
    /// the guest's, on every host platform).
    pub fn type_bits(self) -> u32 {
        match self {
            NodeKind::File => platform::MODE_REG,
            NodeKind::Dir => platform::MODE_DIR,
            NodeKind::Symlink => platform::MODE_LNK,
            NodeKind::Char => platform::MODE_CHR,
            NodeKind::Block => platform::MODE_BLK,
            NodeKind::Fifo => platform::MODE_FIFO,
            NodeKind::Socket => platform::MODE_SOCK,
        }
    }

    /// The directory-entry `d_type` value for this kind.
    pub fn dirent_type(self) -> u32 {
        match self {
            NodeKind::File => platform::DIRENT_REG,
            NodeKind::Dir => platform::DIRENT_DIR,
            NodeKind::Symlink => platform::DIRENT_LNK,
            NodeKind::Char => platform::DIRENT_CHR,
            NodeKind::Block => platform::DIRENT_BLK,
            NodeKind::Fifo => platform::DIRENT_FIFO,
            NodeKind::Socket => platform::DIRENT_SOCK,
        }
    }

    /// Recover a kind from `S_IF*` type bits, if recognized.
    pub fn from_mode(mode: u32) -> Option<NodeKind> {
        Some(match mode & platform::MODE_TYPE_MASK {
            platform::MODE_REG => NodeKind::File,
            platform::MODE_DIR => NodeKind::Dir,
            platform::MODE_LNK => NodeKind::Symlink,
            platform::MODE_CHR => NodeKind::Char,
            platform::MODE_BLK => NodeKind::Block,
            platform::MODE_FIFO => NodeKind::Fifo,
            platform::MODE_SOCK => NodeKind::Socket,
            _ => return None,
        })
    }
}

/// Portable attributes for a node.
///
/// This is the scaffold-facing metadata shape. The scaffold translates it to
/// the platform `stat64`, filling sensible defaults for any `None` timestamp
/// (current time) and computing `st_blocks` from `size`.
#[derive(Debug, Clone)]
pub struct VAttr {
    /// Node kind. Combined with `mode` to form the full `st_mode`.
    pub kind: NodeKind,
    /// Permission bits (e.g. `0o644`). Type bits are derived from `kind`.
    pub mode: u32,
    /// Size in bytes (0 for non-regular files).
    pub size: u64,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Hard-link count. `None` lets the scaffold default it (2 for dirs, 1
    /// otherwise).
    pub nlink: Option<u64>,
    /// Device number for `Char`/`Block` nodes; ignored otherwise.
    pub rdev: u32,
    /// Last-access time; `None` => current time.
    pub atime: Option<SystemTime>,
    /// Last-modification time; `None` => current time.
    pub mtime: Option<SystemTime>,
    /// Last status-change time; `None` => current time.
    pub ctime: Option<SystemTime>,
}

impl VAttr {
    /// Construct a regular-file attr with the given permission bits and size.
    pub fn file(mode: u32, size: u64) -> VAttr {
        VAttr::new(NodeKind::File, mode, size)
    }

    /// Construct a directory attr with the given permission bits.
    pub fn dir(mode: u32) -> VAttr {
        VAttr::new(NodeKind::Dir, mode, 0)
    }

    /// Construct an attr of the given kind with current-time stamps and
    /// uid/gid 0.
    pub fn new(kind: NodeKind, mode: u32, size: u64) -> VAttr {
        VAttr {
            kind,
            mode,
            size,
            uid: 0,
            gid: 0,
            nlink: None,
            rdev: 0,
            atime: None,
            mtime: None,
            ctime: None,
        }
    }
}

/// A single entry returned by [`PathFs::readdir`].
///
/// The `.` and `..` entries are synthesized by the scaffold and must **not**
/// be included.
#[derive(Debug, Clone)]
pub struct VDirEntry {
    /// Entry name (a single path component; no `/`).
    pub name: Vec<u8>,
    /// Entry kind, used for the directory-entry `d_type`.
    pub kind: NodeKind,
}

impl VDirEntry {
    /// Construct an entry from a name and kind.
    pub fn new(name: impl Into<Vec<u8>>, kind: NodeKind) -> VDirEntry {
        VDirEntry {
            name: name.into(),
            kind,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait
//--------------------------------------------------------------------------------------------------

/// A path-addressed filesystem backend.
///
/// Implement the required methods to expose a readable, navigable tree;
/// override the provided methods to add writes, links, xattrs, and a tuned
/// `statfs`. All paths are absolute and begin with `/`; the root is `/`.
///
/// Implementations must be `Send + Sync`: the scaffold may call methods
/// concurrently from multiple FUSE worker threads.
pub trait PathFs: Send + Sync {
    // ---- required: a readable tree -------------------------------------------------------------

    /// Return attributes for the node at `path`, or `ENOENT` if absent.
    fn getattr(&self, path: &[u8]) -> io::Result<VAttr>;

    /// Fetch attributes for several paths at once, returning one result per
    /// path in order. The outer `Result` is a transport-level failure; the
    /// inner per-path `Result` is that path's own getattr outcome. The default
    /// calls [`getattr`](Self::getattr) per path; an RPC-backed provider
    /// overrides it to collapse N round-trips into one.
    fn getattr_many(&self, paths: &[&[u8]]) -> io::Result<Vec<io::Result<VAttr>>> {
        Ok(paths.iter().map(|p| self.getattr(p)).collect())
    }

    /// List the children of the directory at `path` (excluding `.`/`..`).
    fn readdir(&self, path: &[u8]) -> io::Result<Vec<VDirEntry>>;

    /// Read up to `size` bytes from the file at `path` starting at `offset`.
    ///
    /// A short read (fewer than `size` bytes) signals end-of-file; returning
    /// an empty `Vec` means EOF.
    fn read(&self, path: &[u8], offset: u64, size: u32) -> io::Result<Vec<u8>>;

    // ---- provided: mutations (default `ENOSYS`) ------------------------------------------------

    /// Write `data` to the file at `path` starting at `offset`, returning the
    /// number of bytes accepted. Default: `ENOSYS` (read-only filesystem).
    fn write(&self, path: &[u8], offset: u64, data: &[u8]) -> io::Result<usize> {
        let _ = (path, offset, data);
        Err(enosys())
    }

    /// Create a regular file (or special node per `attr.kind`) at `path`.
    /// Default: `ENOSYS`.
    fn create(&self, path: &[u8], attr: &VAttr) -> io::Result<VAttr> {
        let _ = (path, attr);
        Err(enosys())
    }

    /// Create a directory at `path` with the given permission bits. Default:
    /// `ENOSYS`.
    fn mkdir(&self, path: &[u8], mode: u32) -> io::Result<VAttr> {
        let _ = (path, mode);
        Err(enosys())
    }

    /// Remove the file, symlink, special node, or **empty** directory at
    /// `path`. The scaffold enforces directory-emptiness before calling.
    /// Default: `ENOSYS`.
    fn remove(&self, path: &[u8]) -> io::Result<()> {
        let _ = path;
        Err(enosys())
    }

    /// Remove an empty directory at `path`.
    ///
    /// The default implementation checks emptiness (with the same readdir-name
    /// filtering as the scaffold) then calls [`remove`](Self::remove).
    fn rmdir(&self, path: &[u8]) -> io::Result<()> {
        let attr = self.getattr(path)?;
        if attr.kind != NodeKind::Dir {
            return Err(platform::enotdir());
        }
        check_dir_empty_for_rmdir(&self.readdir(path)?)?;
        self.remove(path)
    }

    /// Rename `from` to `to`. The scaffold updates its inode↔path map for the
    /// moved subtree afterward. Default: `ENOSYS`.
    fn rename(&self, from: &[u8], to: &[u8]) -> io::Result<()> {
        let _ = (from, to);
        Err(enosys())
    }

    /// Rename `from` to `to`, honoring Linux `renameat2` flags when supported.
    ///
    /// `flags` uses the Linux constants (`RENAME_NOREPLACE` = 1,
    /// `RENAME_EXCHANGE` = 2). The default rejects `RENAME_EXCHANGE` with
    /// `ENOSYS`, performs a best-effort `RENAME_NOREPLACE` pre-check, then calls
    /// [`rename`](Self::rename). Providers that need atomic noreplace semantics
    /// should override this and enforce them under their own lock.
    fn rename_with_flags(&self, from: &[u8], to: &[u8], flags: u32) -> io::Result<()> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        if flags & RENAME_EXCHANGE != 0 {
            return Err(enosys());
        }
        if flags & RENAME_NOREPLACE != 0 && self.getattr(to).is_ok() {
            return Err(platform::eexist());
        }
        self.rename(from, to)
    }

    /// Apply the subset of `attr` selected by `valid` to the node at `path`,
    /// returning the resulting attributes. Default: `ENOSYS`.
    fn setattr(&self, path: &[u8], attr: &VAttr, valid: SetattrValid) -> io::Result<VAttr> {
        let _ = (path, attr, valid);
        Err(enosys())
    }

    // ---- provided: links (default `ENOSYS`) ----------------------------------------------------

    /// Create a symbolic link at `path` pointing to `target`. Default:
    /// `ENOSYS`.
    fn symlink(&self, path: &[u8], target: &[u8]) -> io::Result<VAttr> {
        let _ = (path, target);
        Err(enosys())
    }

    /// Return the target of the symbolic link at `path`. Default: `ENOSYS`.
    fn readlink(&self, path: &[u8]) -> io::Result<Vec<u8>> {
        let _ = path;
        Err(enosys())
    }

    // ---- provided: extended attributes (default `ENOSYS`) --------------------------------------

    /// Set extended attribute `name` on `path`. Default: `ENOSYS`.
    fn setxattr(&self, path: &[u8], name: &[u8], value: &[u8], flags: u32) -> io::Result<()> {
        let _ = (path, name, value, flags);
        Err(enosys())
    }

    /// Get extended attribute `name` from `path`. Default: `ENOSYS`.
    fn getxattr(&self, path: &[u8], name: &[u8]) -> io::Result<Vec<u8>> {
        let _ = (path, name);
        Err(enosys())
    }

    /// List the extended-attribute names on `path`. Default: empty list.
    fn listxattr(&self, path: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let _ = path;
        Ok(Vec::new())
    }

    /// Remove extended attribute `name` from `path`. Default: `ENOSYS`.
    fn removexattr(&self, path: &[u8], name: &[u8]) -> io::Result<()> {
        let _ = (path, name);
        Err(enosys())
    }

    // ---- provided: durability (default no-op) --------------------------------------------------

    /// Flush buffered writes for the file at `path`. Default: success without
    /// calling the provider (no buffered state in the scaffold).
    fn flush(&self, path: &[u8]) -> io::Result<()> {
        let _ = path;
        Ok(())
    }

    /// Sync the file at `path` to stable storage. Default: success without
    /// calling the provider.
    fn fsync(&self, path: &[u8], datasync: bool) -> io::Result<()> {
        let _ = (path, datasync);
        Ok(())
    }

    /// Refresh directory listing state for the directory at `path`. The
    /// scaffold calls this from `fsyncdir` before rebuilding an open handle's
    /// snapshot. Default: success without calling the provider.
    fn fsyncdir(&self, path: &[u8]) -> io::Result<()> {
        let _ = path;
        Ok(())
    }

    // ---- provided: volume stats ----------------------------------------------------------------

    /// Report filesystem statistics. Default: a generic unbounded volume.
    fn statfs(&self) -> io::Result<statvfs64> {
        Ok(default_statvfs())
    }
}

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// View a guest byte path as a host [`Path`](std::path::Path) (byte-safe;
/// unix hosts only).
///
/// Convenience for providers that map guest paths onto the host filesystem.
/// There is deliberately no Windows counterpart: an arbitrary byte path cannot
/// be represented as a Windows `OsStr`, and guest paths are Linux paths.
#[cfg(unix)]
pub fn as_path(bytes: &[u8]) -> &std::path::Path {
    use std::os::unix::ffi::OsStrExt;
    std::path::Path::new(std::ffi::OsStr::from_bytes(bytes))
}

/// Enforce scaffold rmdir emptiness rules on a full directory listing.
pub fn check_dir_empty_for_rmdir(entries: &[VDirEntry]) -> io::Result<()> {
    let mut visible = 0usize;
    let mut has_invalid = false;
    for entry in entries {
        if entry.name == b"." || entry.name == b".." {
            continue;
        }
        if name_validation::validate_readdir_name(&entry.name).is_ok() {
            visible += 1;
        } else {
            has_invalid = true;
        }
    }
    if visible > 0 {
        return Err(platform::enotempty());
    }
    if has_invalid {
        return Err(platform::eio());
    }
    Ok(())
}

/// An `ENOSYS` error: "operation not supported by this provider".
fn enosys() -> io::Error {
    platform::enosys()
}

/// A generic, effectively-unbounded `statvfs64`.
fn default_statvfs() -> statvfs64 {
    let mut st: statvfs64 = unsafe { std::mem::zeroed() };
    st.f_bsize = 4096;
    st.f_frsize = 4096;
    st.f_namemax = 255;
    st
}
