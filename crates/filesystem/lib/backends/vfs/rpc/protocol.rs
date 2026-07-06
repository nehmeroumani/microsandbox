//! The VFS-op wire protocol: a request/response pair per [`PathFs`] method.
//!
//! These types cross the parent↔child process boundary that separates the
//! controlling process (which runs the user's provider) from the `msb` runtime
//! (which serves FUSE). They are CBOR-encoded ([`to_cbor`]/[`from_cbor`]) and
//! length-framed ([`write_frame`]/[`read_frame`]).
//!
//! Paths and names are raw bytes — never UTF-8-validated strings — and errors
//! carry a **Linux** errno so they round-trip exactly as [`PathFs`] promises.
//!
//! [`PathFs`]: super::super::PathFs

use std::{
    io::{self, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::super::{NodeKind, VAttr, VDirEntry};
use crate::backends::shared::platform;
use crate::statvfs64;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum bytes per read/write payload (matches the FUSE BIG_WRITES default).
pub const MAX_IO_SIZE: u32 = 128 * 1024;

/// Maximum paths in a single `GetAttrMany` batch.
pub const MAX_BATCH_PATHS: usize = 4096;

/// Total path bytes allowed in one `GetAttrMany` request.
pub const MAX_BATCH_PATH_BYTES: usize = 256 * 1024;

/// Maximum directory entries returned in one `ReadDir` response.
pub const MAX_READDIR_ENTRIES: usize = 1 << 20;

/// Maximum size of a single framed message, bounding the allocation a corrupt
/// length prefix can force.
pub const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

/// Maximum symlink target length accepted on the wire.
const MAX_SYMLINK_TARGET: usize = 4096;

/// Maximum extended-attribute value length accepted on the wire.
const MAX_XATTR_VALUE: usize = 64 * 1024;

/// The wire-protocol version, exchanged once via the hello handshake so a skew
/// between the independently-versioned `msb` runtime and the controlling process
/// fails loudly at channel open instead of as an opaque mid-stream decode error.
pub const PROTOCOL_VERSION: u32 = 1;

/// Magic prefix identifying the microsandbox VFS protocol in a hello frame.
const HELLO_MAGIC: [u8; 4] = *b"MVFS";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Wire form of [`VAttr`]. Times are `(seconds, nanos)` since the epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VAttrWire {
    /// [`NodeKind`] encoded as a byte.
    pub kind: u8,
    /// Permission bits (type bits are derived from `kind`).
    pub mode: u32,
    /// Size in bytes.
    pub size: u64,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Hard-link count; `None` lets the scaffold default it.
    pub nlink: Option<u64>,
    /// Device number for `Char`/`Block` nodes.
    pub rdev: u32,
    /// Last-access time; `None` => current time.
    pub atime: Option<(i64, u32)>,
    /// Last-modification time; `None` => current time.
    pub mtime: Option<(i64, u32)>,
    /// Last status-change time; `None` => current time.
    pub ctime: Option<(i64, u32)>,
}

/// One path's result inside an [`VfsResponse::AttrMany`] batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VAttrResult {
    /// Attributes for the path.
    Ok(VAttrWire),
    /// The path's getattr failed with this Linux errno.
    Err(i32),
}

/// Wire form of [`VDirEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VDirEntryWire {
    /// Entry name (a single path component).
    #[serde(with = "serde_bytes")]
    pub name: Vec<u8>,
    /// [`NodeKind`] encoded as a byte.
    pub kind: u8,
}

/// Wire form of the `statvfs64` fields a provider can influence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatFsWire {
    /// Filesystem block size.
    pub bsize: u64,
    /// Fragment size.
    pub frsize: u64,
    /// Total data blocks.
    pub blocks: u64,
    /// Free blocks.
    pub bfree: u64,
    /// Free blocks available to unprivileged users.
    pub bavail: u64,
    /// Total inodes.
    pub files: u64,
    /// Free inodes.
    pub ffree: u64,
    /// Maximum filename length.
    pub namemax: u64,
}

/// One variant per [`PathFs`](super::super::PathFs) method. All `path`/`name`
/// fields are raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)] // variant/field names mirror the PathFs methods 1:1
pub enum VfsRequest {
    GetAttr {
        path: ByteBuf,
    },
    GetAttrMany {
        paths: Vec<ByteBuf>,
    },
    ReadDir {
        path: ByteBuf,
    },
    ReadLink {
        path: ByteBuf,
    },
    Read {
        path: ByteBuf,
        offset: u64,
        size: u32,
    },
    Write {
        path: ByteBuf,
        offset: u64,
        data: ByteBuf,
    },
    Create {
        path: ByteBuf,
        attr: VAttrWire,
    },
    Mkdir {
        path: ByteBuf,
        mode: u32,
    },
    Remove {
        path: ByteBuf,
    },
    Rename {
        from: ByteBuf,
        to: ByteBuf,
        flags: u32,
    },
    SetAttr {
        path: ByteBuf,
        attr: VAttrWire,
        valid: u32,
    },
    Symlink {
        path: ByteBuf,
        target: ByteBuf,
    },
    SetXattr {
        path: ByteBuf,
        name: ByteBuf,
        value: ByteBuf,
        flags: u32,
    },
    GetXattr {
        path: ByteBuf,
        name: ByteBuf,
    },
    ListXattr {
        path: ByteBuf,
    },
    RemoveXattr {
        path: ByteBuf,
        name: ByteBuf,
    },
    Flush {
        path: ByteBuf,
    },
    Fsync {
        path: ByteBuf,
        datasync: bool,
    },
    FsyncDir {
        path: ByteBuf,
    },
    StatFs,
}

/// The reply to a [`VfsRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VfsResponse {
    /// Node attributes (getattr/create/mkdir/setattr/symlink).
    Attr(VAttrWire),
    /// Per-path attributes for a batched getattr, in request order.
    AttrMany(Vec<VAttrResult>),
    /// Directory entries, excluding `.`/`..` (readdir).
    Dir(Vec<VDirEntryWire>),
    /// Raw bytes (read/readlink/getxattr).
    Bytes(ByteBuf),
    /// Extended-attribute names (listxattr).
    Names(Vec<ByteBuf>),
    /// Bytes accepted (write).
    Count(u64),
    /// Filesystem statistics (statfs).
    StatFs(StatFsWire),
    /// Success with no payload.
    Ok,
    /// Failure carrying a Linux errno.
    Err(i32),
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<&VAttr> for VAttrWire {
    fn from(a: &VAttr) -> Self {
        VAttrWire {
            kind: node_kind_to_u8(a.kind),
            mode: a.mode,
            size: a.size,
            uid: a.uid,
            gid: a.gid,
            nlink: a.nlink,
            rdev: a.rdev,
            atime: a.atime.map(time_to_wire),
            mtime: a.mtime.map(time_to_wire),
            ctime: a.ctime.map(time_to_wire),
        }
    }
}

impl VAttrWire {
    /// Convert back into a [`VAttr`], rejecting an unknown node kind.
    pub fn into_vattr(self) -> io::Result<VAttr> {
        Ok(VAttr {
            kind: node_kind_from_u8(self.kind)?,
            mode: self.mode,
            size: self.size,
            uid: self.uid,
            gid: self.gid,
            nlink: self.nlink,
            rdev: self.rdev,
            atime: self.atime.map(wire_to_time),
            mtime: self.mtime.map(wire_to_time),
            ctime: self.ctime.map(wire_to_time),
        })
    }
}

impl From<&VDirEntry> for VDirEntryWire {
    fn from(e: &VDirEntry) -> Self {
        VDirEntryWire {
            name: e.name.clone(),
            kind: node_kind_to_u8(e.kind),
        }
    }
}

impl VDirEntryWire {
    /// Convert back into a [`VDirEntry`].
    pub fn into_entry(self) -> io::Result<VDirEntry> {
        Ok(VDirEntry {
            name: self.name,
            kind: node_kind_from_u8(self.kind)?,
        })
    }
}

impl From<&statvfs64> for StatFsWire {
    #[allow(clippy::unnecessary_cast)]
    fn from(s: &statvfs64) -> Self {
        StatFsWire {
            bsize: s.f_bsize as u64,
            frsize: s.f_frsize as u64,
            blocks: s.f_blocks as u64,
            bfree: s.f_bfree as u64,
            bavail: s.f_bavail as u64,
            files: s.f_files as u64,
            ffree: s.f_ffree as u64,
            namemax: s.f_namemax as u64,
        }
    }
}

impl StatFsWire {
    /// Rebuild a `statvfs64` from the wire fields.
    pub fn into_statvfs(self) -> statvfs64 {
        let mut st: statvfs64 = unsafe { std::mem::zeroed() };
        st.f_bsize = self.bsize as _;
        st.f_frsize = self.frsize as _;
        st.f_blocks = self.blocks as _;
        st.f_bfree = self.bfree as _;
        st.f_bavail = self.bavail as _;
        st.f_files = self.files as _;
        st.f_ffree = self.ffree as _;
        st.f_namemax = self.namemax as _;
        st
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn node_kind_to_u8(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::File => 0,
        NodeKind::Dir => 1,
        NodeKind::Symlink => 2,
        NodeKind::Char => 3,
        NodeKind::Block => 4,
        NodeKind::Fifo => 5,
        NodeKind::Socket => 6,
    }
}

pub(crate) fn node_kind_from_u8(v: u8) -> io::Result<NodeKind> {
    Ok(match v {
        0 => NodeKind::File,
        1 => NodeKind::Dir,
        2 => NodeKind::Symlink,
        3 => NodeKind::Char,
        4 => NodeKind::Block,
        5 => NodeKind::Fifo,
        6 => NodeKind::Socket,
        _ => return Err(bad_data("unknown node kind")),
    })
}

// Times use the standard `timespec` floor convention: `sec` is the floor of the
// instant in whole seconds and `nsec` is always in `[0, 1e9)`.
fn time_to_wire(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let secs = d.as_secs() as i64;
            let nanos = d.subsec_nanos();
            if nanos == 0 {
                (-secs, 0)
            } else {
                (-secs - 1, 1_000_000_000 - nanos)
            }
        }
    }
}

fn wire_to_time((sec, nsec): (i64, u32)) -> SystemTime {
    // A provider can hand back an arbitrary `(sec, nsec)`; the shared
    // `systime` helper builds the `SystemTime` with checked/`unsigned_abs`
    // arithmetic and collapses out-of-range instants to the epoch rather than
    // panicking the FUSE worker decoding the reply.
    super::super::systime(sec, nsec as i64)
}

fn bad_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// CBOR-encode a value into a fresh buffer.
pub fn to_cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).expect("CBOR encoding to a Vec cannot fail");
    buf
}

/// CBOR-decode a value from bytes.
pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    ciborium::from_reader(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Decode a [`VfsRequest`] and reject oversize batches/payloads.
pub fn decode_request(bytes: &[u8]) -> io::Result<VfsRequest> {
    let req: VfsRequest = from_cbor(bytes)?;
    validate_request_limits(&req)?;
    Ok(req)
}

/// Map a decode/validation failure to the Linux errno sent on the wire.
pub fn decode_error_errno(err: &io::Error) -> i32 {
    err.raw_os_error().unwrap_or(platform::LINUX_EINVAL)
}

/// Reject wire requests whose declared sizes exceed protocol limits.
pub fn validate_request_limits(req: &VfsRequest) -> io::Result<()> {
    match req {
        VfsRequest::GetAttrMany { paths } => {
            if paths.len() > MAX_BATCH_PATHS {
                return Err(platform::einval());
            }
            let total_bytes: usize = paths.iter().map(|p| p.len()).sum();
            if total_bytes > MAX_BATCH_PATH_BYTES {
                return Err(platform::einval());
            }
            Ok(())
        }
        VfsRequest::Read { size, .. } if *size > MAX_IO_SIZE => Err(platform::einval()),
        VfsRequest::Write { data, .. } if data.len() > MAX_IO_SIZE as usize => {
            Err(platform::einval())
        }
        VfsRequest::Symlink { target, .. } if target.len() > MAX_SYMLINK_TARGET => {
            Err(platform::enametoolong())
        }
        VfsRequest::SetXattr { value, .. } if value.len() > MAX_XATTR_VALUE => {
            Err(platform::einval())
        }
        _ => Ok(()),
    }
}

/// Write the 8-byte hello: `HELLO_MAGIC` then [`PROTOCOL_VERSION`] big-endian.
pub fn write_hello<W: Write>(w: &mut W) -> io::Result<()> {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&HELLO_MAGIC);
    buf[4..].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    w.write_all(&buf)?;
    w.flush()
}

/// Read and validate a hello, returning the peer's protocol version.
pub fn read_hello<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    if buf[..4] != HELLO_MAGIC {
        return Err(bad_data("vfs: bad protocol magic"));
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if version != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("vfs: unsupported protocol version {version} (supported {PROTOCOL_VERSION})"),
        ));
    }
    Ok(version)
}

/// Write a frame: a big-endian `u32` payload length, a big-endian `u64`
/// `request_id`, then the CBOR payload. The id is reserved for a future
/// multiplexed transport; the serialized transport stamps and echoes it. Frames
/// assume a byte stream (`SOCK_STREAM`).
pub fn write_frame<W: Write>(w: &mut W, request_id: u64, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|&n| n <= MAX_FRAME_LEN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "vfs frame too large"))?;
    // One 12-byte header write instead of two, so a frame costs two writes
    // (header + payload) on the unbuffered stream, matching the Go side.
    let mut head = [0u8; 12];
    head[..4].copy_from_slice(&len.to_be_bytes());
    head[4..].copy_from_slice(&request_id.to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)?;
    w.flush()
}

/// Read a single frame written by [`write_frame`], returning its `request_id`
/// and CBOR payload.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<(u64, Vec<u8>)> {
    let mut head = [0u8; 12];
    r.read_exact(&mut head)?;
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vfs frame too large",
        ));
    }
    let request_id = u64::from_be_bytes([
        head[4], head[5], head[6], head[7], head[8], head[9], head[10], head[11],
    ]);
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok((request_id, buf))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn time_round_trips_including_pre_epoch_subsecond() {
        for t in [
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::new(1_000, 500_000_000),
            UNIX_EPOCH - Duration::from_millis(500),
            UNIX_EPOCH - Duration::new(1, 500_000_000),
            UNIX_EPOCH - Duration::new(2, 0),
        ] {
            assert_eq!(wire_to_time(time_to_wire(t)), t, "time round-trip mismatch");
        }
    }

    #[test]
    fn wire_to_time_handles_extremes_without_panicking() {
        // A hostile/buggy provider can send any (sec, nsec); decoding must not
        // panic the worker. These all exercise the checked_add/checked_sub and
        // `unsigned_abs` paths (the original `-i64::MIN` negation and unchecked
        // add/sub would panic or wrap here).
        let _ = wire_to_time((i64::MAX, 999_999_999));
        let _ = wire_to_time((i64::MIN, 0));
        let _ = wire_to_time((i64::MIN, 999_999_999));
        // Normal values are unaffected.
        assert_eq!(wire_to_time((0, 0)), UNIX_EPOCH);
        assert_eq!(
            wire_to_time((1_000, 500_000_000)),
            UNIX_EPOCH + Duration::new(1_000, 500_000_000)
        );
    }

    #[test]
    fn node_kind_rejects_out_of_range_byte() {
        assert!(node_kind_from_u8(6).is_ok());
        assert!(node_kind_from_u8(7).is_err());
    }

    #[test]
    fn frame_round_trips() {
        let mut buf = Vec::new();
        write_frame(&mut buf, 42, b"hello").unwrap();
        let (id, payload) = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(id, 42);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn max_frame_len_bounds_write_payload() {
        let oversized = vec![0u8; MAX_FRAME_LEN as usize + 1];
        assert!(write_frame(&mut Vec::new(), 1, &oversized).is_err());
    }

    #[test]
    fn decode_request_rejects_oversized_batch() {
        let paths: Vec<ByteBuf> = (0..=MAX_BATCH_PATHS)
            .map(|i| ByteBuf::from(format!("/p{i}").into_bytes()))
            .collect();
        let bytes = to_cbor(&VfsRequest::GetAttrMany { paths });
        assert!(decode_request(&bytes).is_err());
    }

    #[test]
    fn statfs_unit_variant_round_trips() {
        let bytes = to_cbor(&VfsRequest::StatFs);
        assert!(matches!(decode_request(&bytes), Ok(VfsRequest::StatFs)));
    }
}
