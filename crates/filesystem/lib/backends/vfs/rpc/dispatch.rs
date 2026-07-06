//! Server-side RPC dispatch: turn wire requests into [`PathFs`] calls.
//!
//! [`dispatch`] answers one [`VfsRequest`] from a concrete [`PathFs`],
//! translating any host errno to the Linux errno carried on the wire. The
//! [`super::serve`] loop drives it one request at a time per connection, so
//! directory removal (emptiness check + delete) cannot race a concurrent create
//! on the same connection.

use std::io;

use serde_bytes::ByteBuf;

use super::super::PathFs;
use super::super::path_fs::NodeKind;
use super::limits::{clamp_io_size, clamp_write_len};
use super::protocol::{MAX_BATCH_PATHS, MAX_READDIR_ENTRIES, VAttrResult, VfsRequest, VfsResponse};
use crate::SetattrValid;
use crate::backends::shared::{name_validation, platform};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reject absolute guest paths and names the provider must not be asked to serve.
pub(crate) fn validate_request_paths(req: &VfsRequest) -> io::Result<()> {
    use name_validation::{
        validate_provider_path_bytes as path, validate_symlink_target_bytes as target,
        validate_xattr_name_bytes as xattr,
    };
    match req {
        VfsRequest::GetAttr { path: p }
        | VfsRequest::ReadDir { path: p }
        | VfsRequest::ReadLink { path: p }
        | VfsRequest::Read { path: p, .. }
        | VfsRequest::Write { path: p, .. }
        | VfsRequest::Create { path: p, .. }
        | VfsRequest::Mkdir { path: p, .. }
        | VfsRequest::Remove { path: p }
        | VfsRequest::SetAttr { path: p, .. }
        | VfsRequest::ListXattr { path: p }
        | VfsRequest::Flush { path: p }
        | VfsRequest::Fsync { path: p, .. }
        | VfsRequest::FsyncDir { path: p } => path(p),
        VfsRequest::SetXattr { path: p, name, .. }
        | VfsRequest::GetXattr { path: p, name }
        | VfsRequest::RemoveXattr { path: p, name } => {
            path(p)?;
            xattr(name)
        }
        VfsRequest::GetAttrMany { paths } => {
            for p in paths {
                path(p)?;
            }
            Ok(())
        }
        VfsRequest::Rename { from, to, .. } => {
            path(from)?;
            path(to)
        }
        VfsRequest::Symlink { path: p, target: t } => {
            path(p)?;
            target(t)
        }
        VfsRequest::StatFs => Ok(()),
    }
}

/// Answer a [`VfsRequest`] from a concrete [`PathFs`], turning any error into
/// [`VfsResponse::Err`] with its Linux errno.
pub fn dispatch(provider: &dyn PathFs, req: VfsRequest) -> VfsResponse {
    match dispatch_inner(provider, req) {
        Ok(resp) => resp,
        // A provider reports errors in Linux errno — the value the wire and the
        // FUSE guest both speak — so this is a verbatim passthrough.
        Err(e) => VfsResponse::Err(platform::provider_errno_to_wire(e)),
    }
}

fn dispatch_inner(provider: &dyn PathFs, req: VfsRequest) -> io::Result<VfsResponse> {
    validate_request_paths(&req)?;
    Ok(match req {
        VfsRequest::GetAttr { path } => VfsResponse::Attr((&provider.getattr(&path)?).into()),
        VfsRequest::GetAttrMany { paths } => {
            if paths.len() > MAX_BATCH_PATHS {
                return Err(platform::einval());
            }
            VfsResponse::AttrMany(
                paths
                    .iter()
                    .map(|p| match provider.getattr(p) {
                        Ok(a) => VAttrResult::Ok((&a).into()),
                        // Per-path errors are reported in-band (they must not fail
                        // the whole batch).
                        Err(e) => VAttrResult::Err(platform::provider_errno_to_wire(e)),
                    })
                    .collect(),
            )
        }
        VfsRequest::ReadDir { path } => {
            let entries = provider.readdir(&path)?;
            if entries.len() > MAX_READDIR_ENTRIES {
                return Err(platform::einval());
            }
            VfsResponse::Dir(entries.iter().map(Into::into).collect())
        }
        VfsRequest::ReadLink { path } => {
            let t = provider.readlink(&path)?;
            name_validation::validate_symlink_target_bytes(&t)?;
            VfsResponse::Bytes(ByteBuf::from(t))
        }
        VfsRequest::Read { path, offset, size } => {
            let size = clamp_io_size(size)?;
            let data = provider.read(&path, offset, size)?;
            if data.len() > size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vfs: read returned more bytes than requested",
                ));
            }
            VfsResponse::Bytes(ByteBuf::from(data))
        }
        VfsRequest::Write { path, offset, data } => {
            clamp_write_len(data.len())?;
            let count = provider.write(&path, offset, &data)?;
            if count > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vfs: write returned more bytes than sent",
                ));
            }
            VfsResponse::Count(count as u64)
        }
        VfsRequest::Create { path, attr } => {
            VfsResponse::Attr((&provider.create(&path, &attr.into_vattr()?)?).into())
        }
        VfsRequest::Mkdir { path, mode } => {
            VfsResponse::Attr((&provider.mkdir(&path, mode)?).into())
        }
        VfsRequest::Remove { path } => {
            let guest_path = &path;
            match provider.getattr(guest_path) {
                Ok(attr) if attr.kind == NodeKind::Dir => provider.rmdir(guest_path)?,
                Err(e) if e.raw_os_error() != platform::enoent().raw_os_error() => return Err(e),
                _ => provider.remove(guest_path)?,
            }
            VfsResponse::Ok
        }
        VfsRequest::Rename { from, to, flags } => {
            const RENAME_NOREPLACE: u32 = 1;
            const RENAME_EXCHANGE: u32 = 2;
            const KNOWN_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;
            if flags & !KNOWN_RENAME_FLAGS != 0 {
                return Err(platform::einval());
            }
            if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
                return Err(platform::einval());
            }
            if flags & RENAME_EXCHANGE != 0 {
                return Err(platform::enosys());
            }
            provider.rename_with_flags(&from, &to, flags)?;
            VfsResponse::Ok
        }
        VfsRequest::SetAttr { path, attr, valid } => VfsResponse::Attr(
            (&provider.setattr(
                &path,
                &attr.into_vattr()?,
                SetattrValid::from_bits_truncate(valid as _),
            )?)
                .into(),
        ),
        VfsRequest::Symlink { path, target } => {
            VfsResponse::Attr((&provider.symlink(&path, &target)?).into())
        }
        VfsRequest::SetXattr {
            path,
            name,
            value,
            flags,
        } => {
            provider.setxattr(&path, &name, &value, flags)?;
            VfsResponse::Ok
        }
        VfsRequest::GetXattr { path, name } => {
            VfsResponse::Bytes(ByteBuf::from(provider.getxattr(&path, &name)?))
        }
        VfsRequest::ListXattr { path } => {
            let names = provider.listxattr(&path)?;
            for name in &names {
                name_validation::validate_xattr_name_bytes(name)?;
            }
            VfsResponse::Names(names.into_iter().map(ByteBuf::from).collect())
        }
        VfsRequest::RemoveXattr { path, name } => {
            provider.removexattr(&path, &name)?;
            VfsResponse::Ok
        }
        VfsRequest::Flush { path } => {
            provider.flush(&path)?;
            VfsResponse::Ok
        }
        VfsRequest::Fsync { path, datasync } => {
            provider.fsync(&path, datasync)?;
            VfsResponse::Ok
        }
        VfsRequest::FsyncDir { path } => {
            provider.fsyncdir(&path)?;
            VfsResponse::Ok
        }
        VfsRequest::StatFs => VfsResponse::StatFs((&provider.statfs()?).into()),
    })
}
