//! Inode/handle bookkeeping for the [`VirtualFs`](super::VirtualFs) scaffold:
//! the inode↔path map, lookup reference counting, tombstoning, and the path,
//! provisional-inode, and `stat64` helpers the operation modules share.

use std::{
    collections::HashSet,
    ffi::CStr,
    io,
    sync::Arc,
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::types::VNode;
use super::{CachePolicy, NodeKind, PathFs, ROOT_INODE, VAttr, VirtualFs};
use crate::backends::shared::{inode_table::MultikeyBTreeMap, name_validation, platform};
use crate::{Entry, OpenOptions, stat64};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    /// FUSE open options for the cache policy. `always` is the policy-specific
    /// "keep cache" flag (`KEEP_CACHE` for files, `CACHE_DIR` for directories).
    pub(crate) fn cache_options(&self, always: OpenOptions) -> OpenOptions {
        match self.cfg.cache_policy {
            CachePolicy::Never => OpenOptions::DIRECT_IO,
            CachePolicy::Auto => OpenOptions::empty(),
            CachePolicy::Always => always,
        }
    }

    /// Look up a node by inode, or `EBADF` if unknown.
    pub(crate) fn get_node(&self, ino: u64) -> io::Result<Arc<VNode>> {
        self.inodes
            .read()
            .unwrap()
            .get(&ino)
            .cloned()
            .ok_or_else(platform::ebadf)
    }

    /// The current absolute path of an inode.
    ///
    /// An inode the kernel still references after its name was removed or taken
    /// over by a rename is kept resolvable (so FORGET can clean it up) but holds
    /// a tombstone key; resolving it to a path is `ESTALE`.
    pub(crate) fn path_of(&self, ino: u64) -> io::Result<Vec<u8>> {
        let node = self.get_node(ino)?;
        let path = node.path.read().unwrap().clone();
        if is_tombstone(&path) {
            return Err(platform::estale());
        }
        Ok(path)
    }

    /// Get or allocate the inode for `path` and take one FUSE lookup reference
    /// for it, returning the node.
    ///
    /// The get-or-insert and the reference bump happen together under the write
    /// lock, closing the lookup/forget race: `forget_one` evicts a node only
    /// while holding the same write lock and only when its refs are `0`.
    pub(crate) fn intern_and_reference(&self, path: Vec<u8>) -> Arc<VNode> {
        let mut inodes = self.inodes.write().unwrap();
        if let Some(node) = inodes.get_alt(&path).cloned() {
            node.lookup_refs.fetch_add(1, Ordering::Relaxed);
            return node;
        }

        let ino = self.next_inode.fetch_add(1, Ordering::Relaxed);
        let node = Arc::new(VNode {
            inode: ino,
            path: std::sync::RwLock::new(path.clone()),
            lookup_refs: std::sync::atomic::AtomicU64::new(1),
        });
        inodes.insert(ino, path, Arc::clone(&node));
        node
    }

    /// Decrement an inode's lookup refs, evicting it when it reaches zero.
    pub(crate) fn forget_one(&self, ino: u64, count: u64) {
        if ino == ROOT_INODE {
            return;
        }
        let drop_to_zero = {
            let inodes = self.inodes.read().unwrap();
            match inodes.get(&ino) {
                Some(node) => {
                    // Saturating decrement via CAS so a concurrent `lookup`
                    // `fetch_add` is never lost.
                    let mut cur = node.lookup_refs.load(Ordering::Relaxed);
                    loop {
                        let new = cur.saturating_sub(count);
                        match node.lookup_refs.compare_exchange_weak(
                            cur,
                            new,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break new == 0,
                            Err(actual) => cur = actual,
                        }
                    }
                }
                None => false,
            }
        };

        if drop_to_zero {
            let mut inodes = self.inodes.write().unwrap();
            if let Some(node) = inodes.get(&ino)
                && node.lookup_refs.load(Ordering::Relaxed) == 0
            {
                inodes.remove(&ino);
            }
        }
    }

    /// Detach the scaffold's record of `path` after the object behind it is
    /// gone (unlink/rmdir) or its name was taken over by a rename.
    pub(crate) fn invalidate_path(&self, path: &[u8]) {
        detach_path(&mut self.inodes.write().unwrap(), path);
    }

    /// Drop cached directory snapshots after a mutation that may change listings.
    ///
    /// Programmable providers may change directory contents at any time, so open
    /// handles observe fresh listings after mutations. Only handles whose
    /// directory path is listed in `dirs` are refreshed.
    pub(crate) fn invalidate_dir_listings(&self, dirs: &[Vec<u8>]) {
        if dirs.is_empty() {
            return;
        }
        let targets: HashSet<Vec<u8>> = dirs.iter().cloned().collect();
        for dh in self.dir_handles.read().unwrap().values() {
            let path = dh.node.path.read().unwrap().clone();
            if is_tombstone(&path) || !targets.contains(&path) {
                continue;
            }
            *dh.snapshot.lock().unwrap() = None;
        }
    }

    /// Parent listings (and any open handles on a renamed subtree) that must
    /// refresh after `rename`.
    pub(crate) fn invalidate_after_rename(&self, from: &[u8], to: &[u8]) {
        let parent_from = parent_path(from);
        let parent_to = parent_path(to);
        for dh in self.dir_handles.read().unwrap().values() {
            let path = dh.node.path.read().unwrap().clone();
            if is_tombstone(&path) {
                continue;
            }
            if path == parent_from || path == parent_to || is_at_or_under(&path, to) {
                *dh.snapshot.lock().unwrap() = None;
            }
        }
    }

    /// Resolve the guest path for an open file handle, or the appropriate
    /// errno if the handle or path is stale.
    pub(crate) fn file_handle_path(&self, handle: u64) -> io::Result<Vec<u8>> {
        let handles = self.file_handles.read().unwrap();
        let fh = handles.get(&handle).ok_or_else(platform::ebadf)?;
        let live = fh.node.path.read().unwrap().clone();
        if !is_tombstone(&live) {
            return Ok(live);
        }
        Ok(fh.path.clone())
    }

    /// Build a FUSE `Entry` for an interned node from provider attributes.
    pub(crate) fn build_entry(&self, ino: u64, attr: &VAttr) -> Entry {
        Entry {
            inode: ino,
            generation: 0,
            attr: vattr_to_stat(ino, attr),
            attr_flags: 0,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        }
    }

    /// Validate `name` and resolve the absolute path of `parent`'s child named
    /// `name`. Shared by every operation that addresses a named child.
    pub(crate) fn child_path(&self, parent: u64, name: &CStr) -> io::Result<Vec<u8>> {
        name_validation::validate_memfs_name(name)?;
        let path = join(&self.path_of(parent)?, name.to_bytes());
        name_validation::validate_provider_path_bytes(&path)?;
        Ok(path)
    }

    /// Intern a freshly created child `path`, take one FUSE lookup reference,
    /// and build its `Entry`.
    pub(crate) fn intern_entry(&self, path: Vec<u8>, attr: &VAttr) -> Entry {
        let node = self.intern_and_reference(path);
        self.build_entry(node.inode, attr)
    }

    /// The inode number to advertise for a `readdir` entry at `path`.
    ///
    /// Reuses the interned inode when known (so the cookie stays stable across a
    /// later `lookup`); otherwise returns a deterministic [`provisional_inode`]
    /// *without* interning a permanent node (plain `readdir` takes no lookup
    /// reference, so interning here would leak nodes the kernel never FORGETs).
    pub(crate) fn dirent_inode(&self, path: &[u8]) -> u64 {
        match self.inodes.read().unwrap().get_alt(path) {
            Some(node) => node.inode,
            None => provisional_inode(path),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: path utilities
//--------------------------------------------------------------------------------------------------

/// Join a directory path and a single, already-validated child name into an
/// absolute path. `validate_name` rejects empty, `..`, and `/`-containing names
/// before they reach here, so paths cannot escape the subtree.
pub(crate) fn join(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent == b"/" {
        let mut p = Vec::with_capacity(1 + name.len());
        p.push(b'/');
        p.extend_from_slice(name);
        p
    } else {
        let mut p = Vec::with_capacity(parent.len() + 1 + name.len());
        p.extend_from_slice(parent);
        p.push(b'/');
        p.extend_from_slice(name);
        p
    }
}

/// Whether `path` is `base` itself or a descendant of `base`.
pub(crate) fn is_at_or_under(path: &[u8], base: &[u8]) -> bool {
    path == base || (path.len() > base.len() && path.starts_with(base) && path[base.len()] == b'/')
}

/// The parent directory of an absolute path. The parent of `/` is `/`.
pub(crate) fn parent_path(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => b"/".to_vec(),
        Some(idx) => path[..idx].to_vec(),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: inode helpers
//--------------------------------------------------------------------------------------------------

/// A private inode-table key for a node whose name is gone but which the kernel
/// still references. Guest paths always begin with `/`, so a leading NUL can
/// never collide with one.
fn tombstone_key(inode: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8);
    key.push(0);
    key.extend_from_slice(&inode.to_be_bytes());
    key
}

/// Whether `path` is a tombstone key produced by [`tombstone_key`].
pub(crate) fn is_tombstone(path: &[u8]) -> bool {
    path.first() == Some(&0)
}

/// A stable provisional inode for a directory entry that is not yet interned.
///
/// Derived deterministically from the path (64-bit FNV-1a) so repeated listings
/// of an unchanged entry report the same `d_ino`. The top bit is set so a
/// provisional number can never collide with the sequential interned inodes.
pub(crate) fn provisional_inode(path: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash | (1 << 63)
}

/// Like [`provisional_inode`] with extra mixing when two paths collide in one
/// directory listing.
fn provisional_inode_salted(path: &[u8], salt: u64) -> u64 {
    let mut hash = provisional_inode(path) ^ salt;
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    hash | (1 << 63)
}

/// Assign a unique `d_ino` for one `readdir` entry within a single listing.
pub(crate) fn unique_dirent_inode(base: u64, path: &[u8], seen: &mut HashSet<u64>) -> u64 {
    if seen.insert(base) {
        return base;
    }
    let mut salt = 1u64;
    loop {
        let ino = provisional_inode_salted(path, salt);
        if seen.insert(ino) {
            return ino;
        }
        salt += 1;
    }
}

/// Detach `path` from the inode table after the object behind it is gone or its
/// name was taken over by a rename.
///
/// A node the kernel has already forgotten is removed outright. A node still
/// referenced is re-keyed to a private tombstone instead.
pub(crate) fn detach_path(inodes: &mut MultikeyBTreeMap<u64, Vec<u8>, Arc<VNode>>, path: &[u8]) {
    let Some(node) = inodes.get_alt(path).cloned() else {
        return;
    };
    if node.lookup_refs.load(Ordering::Relaxed) == 0 {
        inodes.remove_alt(path);
    } else {
        let tombstone = tombstone_key(node.inode);
        *node.path.write().unwrap() = tombstone.clone();
        inodes.insert(node.inode, tombstone, node);
    }
}

/// After a provider rename, rewrite the inode↔path map for the moved subtree so
/// open handles and cached inodes follow the move.
pub(crate) fn remap_subtree_inodes(
    inodes: &mut MultikeyBTreeMap<u64, Vec<u8>, Arc<VNode>>,
    from: &[u8],
    to: &[u8],
) {
    // Detach any node interned at/under `to` that is not part of the moved
    // subtree — the rename replaces whatever lived at the destination.
    let dest_stale: Vec<Vec<u8>> = inodes
        .iter_alt()
        .map(|(path, _)| path)
        .filter(|path| is_at_or_under(path, to) && !is_at_or_under(path, from))
        .cloned()
        .collect();
    for path in dest_stale {
        detach_path(inodes, &path);
    }

    // Collect every interned path at or under `from`.
    let moved: Vec<(Vec<u8>, u64)> = inodes
        .iter_alt()
        .filter(|(path, _)| is_at_or_under(path, from))
        .map(|(path, &ino)| (path.clone(), ino))
        .collect();

    for (old_path, ino) in moved {
        let mut new_path = to.to_vec();
        new_path.extend_from_slice(&old_path[from.len()..]);

        if let Some(node) = inodes.get(&ino).cloned() {
            *node.path.write().unwrap() = new_path.clone();
            inodes.insert(ino, new_path, node);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: stat64 + time helpers
//--------------------------------------------------------------------------------------------------

/// Split a `SystemTime` into `(seconds, nanos)`, defaulting `None` to now.
fn time_parts(t: Option<SystemTime>) -> (i64, i64) {
    match t {
        Some(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos() as i64),
            Err(_) => (0, 0),
        },
        None => current_timespec(),
    }
}

/// Current wall-clock time as `(seconds, nanos)`.
fn current_timespec() -> (i64, i64) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos() as i64),
        Err(_) => (0, 0),
    }
}

/// Build a `stat64` from an inode number and portable attributes.
pub(crate) fn vattr_to_stat(ino: u64, attr: &VAttr) -> stat64 {
    let mut st: stat64 = unsafe { std::mem::zeroed() };

    let mode = attr.kind.type_bits() | (attr.mode & 0o7777);
    let nlink = attr
        .nlink
        .unwrap_or(if attr.kind == NodeKind::Dir { 2 } else { 1 });

    st.st_ino = ino;

    #[cfg(target_os = "linux")]
    {
        st.st_mode = mode as _;
        st.st_nlink = nlink as _;
        st.st_rdev = attr.rdev as _;
    }

    #[cfg(target_os = "macos")]
    {
        st.st_mode = mode as u16;
        st.st_nlink = nlink as u16;
        st.st_rdev = attr.rdev as i32;
    }

    #[cfg(windows)]
    {
        st.st_mode = mode;
        st.st_nlink = nlink;
        st.st_rdev = attr.rdev as u64;
    }

    st.st_uid = attr.uid;
    st.st_gid = attr.gid;
    // Saturate so a provider reporting a very large size can't surface a
    // negative st_size/st_blocks.
    st.st_size = attr.size.min(i64::MAX as u64) as i64;
    st.st_blksize = 4096;
    st.st_blocks = attr.size.div_ceil(512).min(i64::MAX as u64) as i64;

    let (asec, ansec) = time_parts(attr.atime);
    let (msec, mnsec) = time_parts(attr.mtime);
    let (csec, cnsec) = time_parts(attr.ctime);
    st.st_atime = asec;
    st.st_atime_nsec = ansec;
    st.st_mtime = msec;
    st.st_mtime_nsec = mnsec;
    st.st_ctime = csec;
    st.st_ctime_nsec = cnsec;

    st
}

/// Build a `SystemTime` from seconds + nanoseconds since the epoch, flooring
/// pre-epoch instants. The single timestamp decoder for both guest-supplied
/// setattr values and the RPC wire codec (`wire_to_time` delegates here).
pub(crate) fn systime(sec: i64, nsec: i64) -> SystemTime {
    // A guest or provider can hand back an arbitrary `(sec, nsec)`;
    // `SystemTime`'s `Add`/`Sub` panic on overflow and `-i64::MIN` would overflow
    // the negation, so use checked/`unsigned_abs` forms with an epoch fallback
    // rather than crashing the FUSE worker. An out-of-range timestamp is already
    // meaningless, so collapsing it to the epoch is a safe, lossy default.
    let nsec = nsec.clamp(0, 999_999_999) as u32;
    if sec >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(sec as u64, nsec))
            .unwrap_or(UNIX_EPOCH)
    } else {
        let below = Duration::new(sec.unsigned_abs(), 0).saturating_sub(Duration::new(0, nsec));
        UNIX_EPOCH.checked_sub(below).unwrap_or(UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systime_handles_guest_extremes_without_panicking() {
        // A guest can pass any (sec, nsec) via utimensat/setattr; building the
        // SystemTime must not panic the FUSE worker. These exercise the
        // checked_add/checked_sub, `unsigned_abs`, and nsec-clamp paths (the old
        // unchecked add/sub and `-i64::MIN` negation would panic or wrap here).
        let _ = systime(i64::MAX, 999_999_999);
        let _ = systime(i64::MAX, i64::MAX);
        let _ = systime(i64::MIN, 0);
        let _ = systime(i64::MIN, i64::MAX);
        let _ = systime(-1, 2_000_000_000);

        // Normal values are unaffected.
        assert_eq!(systime(0, 0), UNIX_EPOCH);
        assert_eq!(
            systime(1_000, 500_000_000),
            UNIX_EPOCH + Duration::new(1_000, 500_000_000)
        );
    }
}
