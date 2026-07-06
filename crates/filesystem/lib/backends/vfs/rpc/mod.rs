//! RPC bridge for [`PathFs`](super::PathFs) providers in another process.
//!
//! Because the `msb` runtime serves FUSE in a **separate process** from the
//! controller that defines the filesystem semantics, the provider cannot be a
//! set of in-process callbacks. Instead the runtime runs
//! [`super::VirtualFs<RpcPathFs<T>>`], where [`RpcPathFs`] turns each FUSE op
//! into a [`protocol::VfsRequest`] sent over a [`VfsTransport`] to the
//! controlling process, which runs the real provider (via [`serve`]) and replies
//! with a [`protocol::VfsResponse`].
//!
//! The transport is serialized and the serve loop is single-threaded — one
//! operation in flight per mount — mirroring how the sibling backends handle one
//! request at a time.
//!
//! Layout:
//! - `client` — runtime-side [`RpcPathFs`] proxy over a [`VfsTransport`]
//! - `dispatch` — provider-side request handler
//! - `serve` — provider-side request/response loop
//! - `transport` — serialized socket transport
//! - `mount` — build a runtime [`super::VirtualFs`] over a connected socket

mod client;
mod dispatch;
mod limits;
mod mount;
pub mod protocol;
mod serve;
mod transport;

#[cfg(test)]
mod tests;

pub use client::{RpcPathFs, VfsTransport};
pub use dispatch::dispatch;
pub use mount::{MountStream, unix_socket_backend, unix_socket_backend_with_config};
pub use serve::{serve, serve_unix};
pub use transport::SocketTransport;
