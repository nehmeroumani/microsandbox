//! Construct a runtime-side [`super::super::VirtualFs`] backed by an RPC socket
//! to the provider.

use std::io;
use std::time::Duration;

use super::super::{VirtualFs, VirtualFsConfig};
use super::client::RpcPathFs;
use super::transport::{DEFAULT_CALL_TIMEOUT, SocketTransport};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The AF_UNIX stream type a provider connection uses on this host.
///
/// `std`'s `UnixStream` on unix; `uds_windows::UnixStream` on Windows
/// (AF_UNIX is supported by winsock on Windows 10 1803+, but `std` does not
/// expose it there). Both provide `connect`/`pair`/`try_clone`/
/// `set_read_timeout` and `Read + Write`, so everything above the socket is
/// platform-independent.
#[cfg(unix)]
pub type MountStream = std::os::unix::net::UnixStream;

/// The AF_UNIX stream type a provider connection uses on this host.
#[cfg(windows)]
pub type MountStream = uds_windows::UnixStream;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a [`super::super::VirtualFs`] backend served over a connected
/// Unix-domain socket.
///
/// The socket's peer must run a virtual-mount provider server (e.g. [`super::serve`])
/// that answers [`super::protocol::VfsRequest`]s. This is the construction the
/// `msb` runtime uses to turn an inherited socketpair fd into a mountable
/// filesystem backend.
pub fn unix_socket_backend(
    stream: MountStream,
) -> io::Result<VirtualFs<RpcPathFs<SocketTransport<MountStream>>>> {
    unix_socket_backend_with_config(stream, None, None)
}

/// Like [`unix_socket_backend`] with an explicit [`VirtualFsConfig`] and an
/// optional per-op call timeout (`None` uses the 30-second default).
pub fn unix_socket_backend_with_config(
    stream: MountStream,
    cfg: Option<VirtualFsConfig>,
    call_timeout: Option<Duration>,
) -> io::Result<VirtualFs<RpcPathFs<SocketTransport<MountStream>>>> {
    // Leave a read timeout on the stream for the whole connection: it bounds the
    // hello handshake (an absent peer can't stall boot) and every subsequent
    // `call`'s wait for its reply, so a wedged provider fails the mount instead
    // of pinning a FUSE worker forever.
    stream.set_read_timeout(Some(call_timeout.unwrap_or(DEFAULT_CALL_TIMEOUT)))?;
    let transport = SocketTransport::connect(stream)?;
    let provider = RpcPathFs::new(transport);
    match cfg {
        Some(cfg) => VirtualFs::with_config(provider, cfg),
        None => VirtualFs::new(provider),
    }
}
