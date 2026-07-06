//! Shared request-size limits for RPC client and server dispatch.

use std::io;

use super::protocol::MAX_IO_SIZE;
use crate::backends::shared::platform;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Clamp a read/write size to the wire maximum.
pub(crate) fn clamp_io_size(size: u32) -> io::Result<u32> {
    if size > MAX_IO_SIZE {
        return Err(platform::einval());
    }
    Ok(size)
}

/// Reject writes larger than the wire maximum.
pub(crate) fn clamp_write_len(len: usize) -> io::Result<()> {
    if len > MAX_IO_SIZE as usize {
        return Err(platform::einval());
    }
    Ok(())
}
