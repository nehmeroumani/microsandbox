//! Directory operations for [`VirtualFs`](super::VirtualFs): opendir, readdir,
//! readdirplus, fsyncdir, releasedir, and the per-handle snapshot machinery.

use std::io;
use std::sync::{Arc, Mutex};

use super::types::{VDirHandle, VSnapEntry};
use super::*;
use crate::backends::shared::{dir_snapshot, name_validation, platform};
use crate::{DirEntry, Entry, OpenOptions};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    pub(crate) fn do_opendir(&self, ino: u64) -> io::Result<(Option<u64>, OpenOptions)> {
        let path = self.path_of(ino)?;
        let node = self.get_node(ino)?;
        if self.provider.getattr(&path)?.kind != NodeKind::Dir {
            return Err(platform::enotdir());
        }
        let handle = self
            .next_handle
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.dir_handles.write().unwrap().insert(
            handle,
            Arc::new(VDirHandle {
                node,
                snapshot: Mutex::new(None),
            }),
        );
        Ok((Some(handle), self.cache_options(OpenOptions::CACHE_DIR)))
    }

    pub(crate) fn do_readdir(
        &self,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        self.serve_dir(ino, handle, size, offset, FUSE_DIRENT_HEADER)
    }

    pub(crate) fn do_readdirplus(
        &self,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        let dir_path = self.path_of(ino)?;
        let entries = self.serve_dir(ino, handle, size, offset, FUSE_DIRENTPLUS_HEADER)?;

        // Fetch every child's attributes in one batched provider call.
        // `.`/`..` are synthesized and carry no plus-attrs.
        let children: Vec<Vec<u8>> = entries
            .iter()
            .filter(|de| de.name != b"." && de.name != b"..")
            .map(|de| join(&dir_path, de.name))
            .collect();
        // The provider owns batching/chunking; this page is already bounded to a
        // single reply buffer by `serve_dir`, so one call suffices.
        let refs: Vec<&[u8]> = children.iter().map(|p| p.as_slice()).collect();
        let attrs = self.provider.getattr_many(&refs)?;
        if attrs.len() != children.len() {
            return Err(platform::eio());
        }

        let mut children = children.into_iter();
        let mut attrs = attrs.into_iter();
        let mut result = Vec::with_capacity(entries.len());
        for de in entries {
            if de.name == b"." || de.name == b".." {
                continue;
            }
            let child = children.next().expect("one child path per non-dot entry");
            let attr = match attrs.next().expect("one attr result per child path") {
                Ok(attr) => attr,
                // A child that vanished between the snapshot and this per-child
                // getattr (programmable providers mutate freely) is skipped, not
                // fatal — matching memfs, which drops entries it cannot resolve.
                // Skipping *before* interning is essential: failing the whole
                // call here would still have taken a lookup reference for every
                // earlier child, and the kernel discards a failed readdirplus
                // reply without ever FORGETting them, leaking those nodes.
                Err(_) => continue,
            };
            // readdirplus *does* take a lookup reference, so intern a real node.
            let node = self.intern_and_reference(child);
            let entry = self.build_entry(node.inode, &attr);
            let mut de = de;
            de.ino = node.inode;
            result.push((de, entry));
        }
        Ok(result)
    }

    pub(crate) fn do_fsyncdir(&self, ino: u64, handle: u64) -> io::Result<()> {
        let dh = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .cloned()
            .ok_or_else(platform::ebadf)?;
        if dh.node.inode != ino {
            return Err(platform::ebadf());
        }
        let path = self.path_of(ino)?;
        self.provider.fsyncdir(&path)?;
        *dh.snapshot.lock().unwrap() = None;
        Ok(())
    }

    pub(crate) fn do_releasedir(&self, handle: u64) -> io::Result<()> {
        self.dir_handles.write().unwrap().remove(&handle);
        Ok(())
    }

    /// Build (on first call) and serve one page of a directory handle's entry
    /// snapshot, bounded to `size` bytes of `header_bytes`-per-entry dirents so
    /// the page always fits the kernel's reply buffer.
    fn serve_dir(
        &self,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
        header_bytes: usize,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        let dh = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .cloned()
            .ok_or_else(platform::ebadf)?;

        let mut snapshot = dh.snapshot.lock().unwrap();
        if snapshot.is_none() {
            if offset > 0 {
                return Err(platform::eagain());
            }
            *snapshot = Some(self.build_snapshot(ino)?);
        }
        let snap = snapshot.as_ref().unwrap();
        // Serve only the prefix that fits `size`. The existing helper filters by
        // `offset` within the slice it is given, so truncating the slice to
        // `[..end]` yields exactly the entries in `(offset, end)`.
        let end = page_end(snap, offset, size, header_bytes);
        Ok(dir_snapshot::serve_snapshot_entries(&snap[..end], offset))
    }

    /// Build a point-in-time directory snapshot from the provider.
    fn build_snapshot(&self, ino: u64) -> io::Result<Vec<VSnapEntry>> {
        let dir_path = self.path_of(ino)?;
        let children = self.provider.readdir(&dir_path)?;

        let parent = parent_path(&dir_path);
        let parent_ino = self.dirent_inode(&parent);

        let mut entries = Vec::with_capacity(children.len() + 2);
        let mut seen_inodes = std::collections::HashSet::new();
        entries.push(VSnapEntry {
            name: b".".to_vec(),
            inode: unique_dirent_inode(ino, &dir_path, &mut seen_inodes),
            offset: 0,
            file_type: platform::DIRENT_DIR,
        });
        entries.push(VSnapEntry {
            name: b"..".to_vec(),
            inode: unique_dirent_inode(parent_ino, &parent, &mut seen_inodes),
            offset: 0,
            file_type: platform::DIRENT_DIR,
        });

        for child in children {
            // Skip any entry whose name the scaffold cannot represent rather
            // than failing the whole listing.
            if name_validation::validate_readdir_name(&child.name).is_err() {
                tracing::debug!(
                    path = ?String::from_utf8_lossy(&dir_path),
                    name = ?String::from_utf8_lossy(&child.name),
                    "vfs: skipping unrepresentable readdir name from provider"
                );
                continue;
            }
            let child_path = join(&dir_path, &child.name);
            // Skip entries whose absolute path the scaffold would reject on a
            // later `lookup` (e.g. it exceeds PATH_MAX): listing a name that
            // cannot then be stat'd or opened makes `ls` and `stat` disagree.
            if name_validation::validate_provider_path_bytes(&child_path).is_err() {
                tracing::debug!(
                    path = ?String::from_utf8_lossy(&dir_path),
                    name = ?String::from_utf8_lossy(&child.name),
                    "vfs: skipping readdir entry whose absolute path is unrepresentable"
                );
                continue;
            }
            let inode = unique_dirent_inode(
                self.dirent_inode(&child_path),
                &child_path,
                &mut seen_inodes,
            );
            entries.push(VSnapEntry {
                name: child.name,
                inode,
                offset: 0,
                file_type: child.kind.dirent_type(),
            });
        }

        for (i, entry) in entries.iter_mut().enumerate() {
            entry.offset = (i + 1) as u64;
        }

        Ok(entries)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The index one past the last snapshot entry that fits in a `size`-byte FUSE
/// reply buffer, scanning entries whose cookie is strictly greater than
/// `offset`. Always includes at least one entry past `offset` (the kernel
/// guarantees room for one), so a non-empty directory never stalls. Bounding the
/// page here is what keeps `readdirplus` from taking lookup references for
/// entries the kernel's reply buffer would drop (which it would never `FORGET`).
fn page_end(entries: &[VSnapEntry], offset: u64, size: u32, header_bytes: usize) -> usize {
    let start = entries
        .iter()
        .position(|e| e.offset > offset)
        .unwrap_or(entries.len());
    let budget = size as usize;
    let mut used = 0usize;
    let mut end = start;
    for (i, e) in entries.iter().enumerate().skip(start) {
        let cost = (header_bytes + e.name.len() + 7) & !7;
        // Always take the first entry; stop before the page would exceed `size`.
        if i > start && used.saturating_add(cost) > budget {
            break;
        }
        used = used.saturating_add(cost);
        end = i + 1;
    }
    end
}
