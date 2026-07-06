//! File operations for [`VirtualFs`](super::VirtualFs): open, create, read,
//! write, flush, fsync, fallocate, release, lseek, and the zero-copy staging
//! file each FUSE worker uses to move bytes to/from the provider.

use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::types::VFileHandle;
use super::*;
use crate::backends::shared::platform;
use crate::{Entry, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    pub(crate) fn do_open(&self, ino: u64, flags: u32) -> io::Result<(Option<u64>, OpenOptions)> {
        // Consult the provider for the live kind: a programmable backend can
        // turn a path from file to dir (or back), so a cached kind would go
        // stale and produce wrong EISDIR/ENOTDIR decisions.
        let path = self.path_of(ino)?;
        let node = self.get_node(ino)?;
        let mut attr = self.provider.getattr(&path)?;
        if attr.kind == NodeKind::Dir {
            return Err(platform::eisdir());
        }

        // Honor O_TRUNC by asking the provider to zero the file.
        if flags & GUEST_O_TRUNC != 0 {
            attr.size = 0;
            match self.provider.setattr(&path, &attr, SetattrValid::SIZE) {
                Ok(_) => {}
                // The provider's error already carries a Linux errno, so compare
                // against the Linux constant (host ENOSYS differs on macOS).
                Err(e) if e.raw_os_error() == platform::enosys().raw_os_error() => {
                    return Err(platform::eopnotsupp());
                }
                Err(e) => return Err(e),
            }
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.file_handles
            .write()
            .unwrap()
            .insert(handle, Arc::new(VFileHandle { node, path }));
        Ok((Some(handle), self.cache_options(OpenOptions::KEEP_CACHE)))
    }

    pub(crate) fn do_create(
        &self,
        parent: u64,
        name: &std::ffi::CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        let child = self.child_path(parent, name)?;
        let req = VAttr::file((mode & 0o7777) & !(umask & 0o7777), 0);
        let attr = self.provider.create(&child, &req)?;
        self.invalidate_dir_listings(&[parent_path(&child)]);
        let node = self.intern_and_reference(child.clone());
        let entry = self.build_entry(node.inode, &attr);

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.file_handles
            .write()
            .unwrap()
            .insert(handle, Arc::new(VFileHandle { node, path: child }));
        Ok((
            entry,
            Some(handle),
            self.cache_options(OpenOptions::KEEP_CACHE),
        ))
    }

    pub(crate) fn do_read(
        &self,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
    ) -> io::Result<usize> {
        let path = self.file_handle_path(handle)?;
        let req_size = size.min(MAX_IO_SIZE);
        let data = self.provider.read(&path, offset, req_size)?;
        // A provider returning more than requested must not be silently
        // truncated (the kernel would never re-request the dropped tail).
        if data.len() > req_size as usize {
            return Err(platform::eio());
        }
        let count = data.len();
        if count == 0 {
            return Ok(0);
        }

        with_staging_file(|staging| {
            let written = file_write_at(staging, &data, 0).map_err(platform::linux_error)?;
            if written == 0 {
                return Ok(0);
            }
            w.write_from(staging, written, 0)
        })
    }

    pub(crate) fn do_write(
        &self,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
    ) -> io::Result<usize> {
        let path = self.file_handle_path(handle)?;

        // Drain the guest's data into the staging file, then read it back.
        let buf = with_staging_file(|staging| {
            let count = r.read_to(staging, size as usize, 0)?;
            if count == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; count];
            let read_back = file_read_at(staging, &mut buf, 0).map_err(platform::linux_error)?;
            buf.truncate(read_back);
            Ok(buf)
        })?;

        if buf.is_empty() {
            return Ok(0);
        }

        let count = self.provider.write(&path, offset, &buf)?;
        if count > buf.len() {
            return Err(platform::eio());
        }
        Ok(count)
    }

    pub(crate) fn do_flush(&self, handle: u64) -> io::Result<()> {
        let path = self.file_handle_path(handle)?;
        self.provider.flush(&path)
    }

    pub(crate) fn do_fsync(&self, handle: u64, datasync: bool) -> io::Result<()> {
        let path = self.file_handle_path(handle)?;
        self.provider.fsync(&path, datasync)
    }

    pub(crate) fn do_fallocate(
        &self,
        ino: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        if mode != 0 {
            return Err(platform::eopnotsupp());
        }
        let path = self.path_of(ino)?;
        let new_end = offset.checked_add(length).ok_or_else(platform::einval)?;
        if new_end > i64::MAX as u64 {
            return Err(platform::efbig());
        }
        let mut target = self.provider.getattr(&path)?;
        if new_end > target.size {
            target.size = new_end;
            self.provider.setattr(&path, &target, SetattrValid::SIZE)?;
        }
        Ok(())
    }

    pub(crate) fn do_release(&self, handle: u64, flush: bool) -> io::Result<()> {
        // Always drop the handle, even when the flush fails: the kernel does not
        // retry RELEASE, so an early return here would leak the handle entry and
        // the `VNode` it pins, blocking the inode from ever being evicted. Surface
        // the flush error to the caller, but only after removing the handle.
        let result = if flush {
            self.file_handle_path(handle)
                .and_then(|path| self.provider.flush(&path))
        } else {
            Ok(())
        };
        self.file_handles.write().unwrap().remove(&handle);
        result
    }

    pub(crate) fn do_lseek(&self, ino: u64, offset: u64, whence: u32) -> io::Result<u64> {
        let path = self.path_of(ino)?;
        let size = self.provider.getattr(&path)?.size;
        match whence {
            SEEK_SET => Ok(offset),
            SEEK_END => {
                let pos = (size as i64)
                    .checked_add(offset as i64)
                    .ok_or_else(platform::einval)?;
                if pos < 0 {
                    return Err(platform::einval());
                }
                Ok(pos as u64)
            }
            SEEK_DATA => {
                if offset >= size {
                    Err(platform::enxio())
                } else {
                    Ok(offset)
                }
            }
            SEEK_HOLE => {
                if offset >= size {
                    Err(platform::enxio())
                } else {
                    Ok(size)
                }
            }
            _ => Err(platform::einval()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Positional write to `f`, without moving any shared cursor.
pub(crate) fn file_write_at(f: &File, buf: &[u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.write_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        f.seek_write(buf, offset)
    }
}

/// Positional read from `f`, without moving any shared cursor.
pub(crate) fn file_read_at(f: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        f.seek_read(buf, offset)
    }
}

/// Create a staging file for ZeroCopy I/O data transfer.
fn create_staging_file() -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;
        let name = std::ffi::CString::new("virtual-mount-staging").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    // macOS and Windows: an anonymous temp file (delete-on-close on Windows)
    // supports the same positional I/O.
    #[cfg(not(target_os = "linux"))]
    {
        tempfile::tempfile()
    }
}

thread_local! {
    static STAGING_FILE: RefCell<Option<File>> = const { RefCell::new(None) };
}

/// Run a closure against this thread's staging file (one per FUSE worker).
fn with_staging_file<R>(f: impl FnOnce(&File) -> io::Result<R>) -> io::Result<R> {
    STAGING_FILE.with(|slot| {
        let mut file = slot.borrow_mut();
        if file.is_none() {
            *file = Some(create_staging_file()?);
        }
        f(file.as_ref().unwrap())
    })
}
