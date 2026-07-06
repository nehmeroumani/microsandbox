//! [`RpcPathFs`] — a [`PathFs`] whose semantics live behind a [`VfsTransport`].
//!
//! Each `PathFs` call is turned into a [`VfsRequest`], sent over the transport,
//! and decoded from the [`VfsResponse`]. In production the transport is a socket
//! to the controlling process; in tests it is a loopback channel.
//! [`super::dispatch`] is the mirror image — the server side that answers a
//! [`VfsRequest`] from a real `PathFs`.

use std::io;

use serde_bytes::ByteBuf;

use super::super::{PathFs, VAttr, VDirEntry};
use super::limits::clamp_io_size;
use super::protocol::{MAX_BATCH_PATHS, MAX_IO_SIZE, VAttrResult, VfsRequest, VfsResponse};
use crate::backends::shared::platform;
use crate::{SetattrValid, statvfs64};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A request/response channel to the process that owns the real [`PathFs`] provider.
///
/// Implementations must be `Send + Sync`: the scaffold calls the provider
/// concurrently from multiple FUSE worker threads.
pub trait VfsTransport: Send + Sync {
    /// Send one request and block for its response.
    fn call(&self, req: VfsRequest) -> io::Result<VfsResponse>;
}

/// A [`PathFs`] backed by a [`VfsTransport`].
pub struct RpcPathFs<T: VfsTransport> {
    transport: T,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<T: VfsTransport> RpcPathFs<T> {
    /// Wrap a transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn path_bytes(p: &[u8]) -> ByteBuf {
    ByteBuf::from(p.to_vec())
}

/// Map an unexpected (or `Err`) response to an `io::Error`.
fn unexpected(resp: VfsResponse) -> io::Error {
    match resp {
        VfsResponse::Err(errno) => io::Error::from_raw_os_error(errno),
        _ => platform::eio(),
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<T: VfsTransport> PathFs for RpcPathFs<T> {
    fn getattr(&self, path: &[u8]) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::GetAttr {
            path: path_bytes(path),
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn getattr_many(&self, paths: &[&[u8]]) -> io::Result<Vec<io::Result<VAttr>>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut all = Vec::with_capacity(paths.len());
        for chunk in paths.chunks(MAX_BATCH_PATHS) {
            let wire = chunk.iter().map(|p| path_bytes(p)).collect();
            match self
                .transport
                .call(VfsRequest::GetAttrMany { paths: wire })?
            {
                VfsResponse::AttrMany(results) => {
                    if results.len() != chunk.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vfs: getattr_many returned a mismatched number of results",
                        ));
                    }
                    all.extend(results.into_iter().map(|r| match r {
                        VAttrResult::Ok(a) => a.into_vattr(),
                        VAttrResult::Err(errno) => Err(io::Error::from_raw_os_error(errno)),
                    }));
                }
                other => return Err(unexpected(other)),
            }
        }
        Ok(all)
    }

    fn readdir(&self, path: &[u8]) -> io::Result<Vec<VDirEntry>> {
        match self.transport.call(VfsRequest::ReadDir {
            path: path_bytes(path),
        })? {
            VfsResponse::Dir(entries) => entries.into_iter().map(|e| e.into_entry()).collect(),
            other => Err(unexpected(other)),
        }
    }

    fn read(&self, path: &[u8], offset: u64, size: u32) -> io::Result<Vec<u8>> {
        let size = clamp_io_size(size)?;
        match self.transport.call(VfsRequest::Read {
            path: path_bytes(path),
            offset,
            size,
        })? {
            VfsResponse::Bytes(b) => {
                // A reply longer than requested is a peer contract violation:
                // truncating it would drop the tail, so fail loudly instead.
                if b.len() > size as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vfs: read returned more bytes than requested",
                    ));
                }
                Ok(b.into_vec())
            }
            other => Err(unexpected(other)),
        }
    }

    fn write(&self, path: &[u8], offset: u64, data: &[u8]) -> io::Result<usize> {
        if data.len() > MAX_IO_SIZE as usize {
            return Err(platform::einval());
        }
        match self.transport.call(VfsRequest::Write {
            path: path_bytes(path),
            offset,
            data: ByteBuf::from(data.to_vec()),
        })? {
            VfsResponse::Count(n) => {
                let n = n as usize;
                if n > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vfs: write returned more bytes than sent",
                    ));
                }
                Ok(n)
            }
            other => Err(unexpected(other)),
        }
    }

    fn create(&self, path: &[u8], attr: &VAttr) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::Create {
            path: path_bytes(path),
            attr: attr.into(),
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn mkdir(&self, path: &[u8], mode: u32) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::Mkdir {
            path: path_bytes(path),
            mode,
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn remove(&self, path: &[u8]) -> io::Result<()> {
        match self.transport.call(VfsRequest::Remove {
            path: path_bytes(path),
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn rmdir(&self, path: &[u8]) -> io::Result<()> {
        // Server-side Remove routes directory removal through rmdir().
        self.remove(path)
    }

    fn rename(&self, from: &[u8], to: &[u8]) -> io::Result<()> {
        self.rename_with_flags(from, to, 0)
    }

    fn rename_with_flags(&self, from: &[u8], to: &[u8], flags: u32) -> io::Result<()> {
        match self.transport.call(VfsRequest::Rename {
            from: path_bytes(from),
            to: path_bytes(to),
            flags,
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn setattr(&self, path: &[u8], attr: &VAttr, valid: SetattrValid) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::SetAttr {
            path: path_bytes(path),
            attr: attr.into(),
            valid: valid.bits(),
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn symlink(&self, path: &[u8], target: &[u8]) -> io::Result<VAttr> {
        match self.transport.call(VfsRequest::Symlink {
            path: path_bytes(path),
            target: ByteBuf::from(target.to_vec()),
        })? {
            VfsResponse::Attr(a) => a.into_vattr(),
            other => Err(unexpected(other)),
        }
    }

    fn readlink(&self, path: &[u8]) -> io::Result<Vec<u8>> {
        match self.transport.call(VfsRequest::ReadLink {
            path: path_bytes(path),
        })? {
            VfsResponse::Bytes(b) => Ok(b.into_vec()),
            other => Err(unexpected(other)),
        }
    }

    fn setxattr(&self, path: &[u8], name: &[u8], value: &[u8], flags: u32) -> io::Result<()> {
        match self.transport.call(VfsRequest::SetXattr {
            path: path_bytes(path),
            name: ByteBuf::from(name.to_vec()),
            value: ByteBuf::from(value.to_vec()),
            flags,
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn getxattr(&self, path: &[u8], name: &[u8]) -> io::Result<Vec<u8>> {
        match self.transport.call(VfsRequest::GetXattr {
            path: path_bytes(path),
            name: ByteBuf::from(name.to_vec()),
        })? {
            VfsResponse::Bytes(b) => Ok(b.into_vec()),
            other => Err(unexpected(other)),
        }
    }

    fn listxattr(&self, path: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        match self.transport.call(VfsRequest::ListXattr {
            path: path_bytes(path),
        })? {
            VfsResponse::Names(names) => Ok(names.into_iter().map(ByteBuf::into_vec).collect()),
            other => Err(unexpected(other)),
        }
    }

    fn removexattr(&self, path: &[u8], name: &[u8]) -> io::Result<()> {
        match self.transport.call(VfsRequest::RemoveXattr {
            path: path_bytes(path),
            name: ByteBuf::from(name.to_vec()),
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn statfs(&self) -> io::Result<statvfs64> {
        match self.transport.call(VfsRequest::StatFs)? {
            VfsResponse::StatFs(s) => Ok(s.into_statvfs()),
            other => Err(unexpected(other)),
        }
    }

    fn flush(&self, path: &[u8]) -> io::Result<()> {
        match self.transport.call(VfsRequest::Flush {
            path: path_bytes(path),
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn fsync(&self, path: &[u8], datasync: bool) -> io::Result<()> {
        match self.transport.call(VfsRequest::Fsync {
            path: path_bytes(path),
            datasync,
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn fsyncdir(&self, path: &[u8]) -> io::Result<()> {
        match self.transport.call(VfsRequest::FsyncDir {
            path: path_bytes(path),
        })? {
            VfsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }
}
