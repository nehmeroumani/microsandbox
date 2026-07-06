//! A serialized [`VfsTransport`] over a duplex byte stream (e.g. an inherited
//! `SOCK_STREAM` socketpair).
//!
//! Each [`call`](VfsTransport::call) writes one framed request and blocks for
//! its reply under a single mutex, so concurrent FUSE worker threads take turns
//! on the wire. This is the in-process analogue of how the sibling backends
//! serve one operation at a time; a wedged provider is bounded by the read
//! timeout the constructor sets on the stream (a slow reply then fails the mount
//! rather than pinning a worker forever). The `request_id` is stamped and echoed
//! by the peer, leaving room to evolve into a multiplexed transport without a
//! wire break.

use std::io::{self, Read, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::client::VfsTransport;
use super::protocol::{self, VfsRequest, VfsResponse};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default time to wait for a single RPC response (and the hello handshake) when
/// a mount does not set its own timeout. Long enough for a normal provider,
/// short enough that a wedged one fails the mount instead of pinning it for
/// minutes. The mount installs this as the stream's read timeout.
pub(crate) const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A serialized [`VfsTransport`] over any duplex byte stream.
pub struct SocketTransport<S> {
    inner: Mutex<S>,
    next_id: AtomicU64,
    peer_version: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<S: Read + Write + Send> SocketTransport<S> {
    /// Wrap a stream and perform the requester half of the hello handshake:
    /// write our hello, then read and validate the peer's.
    pub fn connect(mut stream: S) -> io::Result<Self> {
        protocol::write_hello(&mut stream)?;
        let peer_version = protocol::read_hello(&mut stream)?;
        Ok(Self::with_peer_version(stream, peer_version))
    }

    /// Wrap a stream *without* a handshake, assuming a peer that handshakes out
    /// of band (used by tests).
    pub fn new(stream: S) -> Self {
        Self::with_peer_version(stream, protocol::PROTOCOL_VERSION)
    }

    pub(crate) fn with_peer_version(stream: S, peer_version: u32) -> Self {
        Self {
            inner: Mutex::new(stream),
            next_id: AtomicU64::new(1),
            peer_version,
        }
    }

    /// Peer protocol version from the hello handshake.
    pub fn peer_protocol_version(&self) -> u32 {
        self.peer_version
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<S: Read + Write + Send> VfsTransport for SocketTransport<S> {
    fn call(&self, req: VfsRequest) -> io::Result<VfsResponse> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let payload = protocol::to_cbor(&req);
        let mut stream = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        protocol::write_frame(&mut *stream, id, &payload)?;
        let (resp_id, resp_bytes) = protocol::read_frame(&mut *stream)?;
        // Calls are serialized, so the reply must echo the id we just stamped. A
        // mismatch means the stream has desynced — e.g. a prior call timed out and
        // returned `Err`, but its late reply is still buffered and we have now read
        // it as the answer to *this* request. Accepting it would hand the caller
        // another path's data; fail loudly instead, the same way `read`/`write`
        // reject over-long replies. (The stream stays shifted, so subsequent calls
        // also error out, degrading the mount to EIO rather than silent corruption.)
        if resp_id != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vfs: transport response id did not match request id",
            ));
        }
        protocol::from_cbor(&resp_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A duplex stream whose writes are discarded and whose reads replay a fixed
    /// buffer — enough to feed `call` one canned response frame.
    struct Canned {
        reads: Cursor<Vec<u8>>,
    }

    impl Read for Canned {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads.read(buf)
        }
    }

    impl Write for Canned {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn call_rejects_mismatched_response_id() {
        // Frame a reply stamped with an id the client will never have sent (its
        // `next_id` starts at 1). A stale/desynced reply like this must be
        // rejected as InvalidData rather than handed back as this call's answer.
        let payload = protocol::to_cbor(&VfsResponse::Ok);
        let mut framed = Vec::new();
        protocol::write_frame(&mut framed, 999, &payload).unwrap();

        let transport = SocketTransport::new(Canned {
            reads: Cursor::new(framed),
        });
        let err = transport.call(VfsRequest::StatFs).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
