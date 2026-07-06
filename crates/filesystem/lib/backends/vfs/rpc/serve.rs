//! Reference VFS RPC server loop: run a [`PathFs`] provider over a byte stream.
//!
//! Run this on the controlling end of a connection while the runtime serves the
//! guest via [`super::mount::unix_socket_backend`]. Like the sibling backends,
//! requests are handled one at a time, so mutating ops (e.g. rmdir's
//! emptiness check + delete) cannot race each other on the same connection.

use std::io::{self, Read, Write};
use std::sync::Arc;

use super::super::PathFs;
use super::dispatch::dispatch;
use super::mount::MountStream;
use super::protocol::{
    MAX_FRAME_LEN, VfsResponse, decode_error_errno, decode_request, read_frame, read_hello,
    to_cbor, write_frame, write_hello,
};
use crate::backends::shared::platform;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the request/response loop for one virtual mount over a connected
/// AF_UNIX stream ([`MountStream`]).
pub fn serve_unix(stream: MountStream, provider: Arc<dyn PathFs>) -> io::Result<()> {
    let reader = stream.try_clone()?;
    serve(reader, stream, provider)
}

/// Like [`serve_unix`] with separate read and write halves of one connection.
///
/// Performs the responder half of the hello handshake, then reads framed CBOR
/// requests, dispatches each to `provider`, and writes replies. Returns `Ok(())`
/// on a clean EOF (the runtime closed the channel); a write failure returns the
/// error on this same thread, ending the loop cleanly.
pub fn serve<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    provider: Arc<dyn PathFs>,
) -> io::Result<()> {
    read_hello(&mut reader)?;
    write_hello(&mut writer)?;

    loop {
        let (id, req_bytes) = match read_frame(&mut reader) {
            Ok(frame) => frame,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let resp = match decode_request(&req_bytes) {
            Ok(req) => dispatch(provider.as_ref(), req),
            Err(err) => VfsResponse::Err(decode_error_errno(&err)),
        };
        let mut payload = to_cbor(&resp);
        if payload.len() > MAX_FRAME_LEN as usize {
            payload = to_cbor(&VfsResponse::Err(
                platform::eio()
                    .raw_os_error()
                    .unwrap_or(platform::LINUX_EIO),
            ));
        }
        write_frame(&mut writer, id, &payload)?;
    }
}
