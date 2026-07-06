//! Metadata operations for [`VirtualFs`](super::VirtualFs): lookup, getattr,
//! setattr, readlink, and access.

use std::ffi::CStr;
use std::io;
use std::time::{Duration, SystemTime};

use super::*;
use crate::backends::shared::{name_validation, platform};
use crate::{Context, Entry, SetattrValid, stat64};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    pub(crate) fn do_lookup(&self, parent: u64, name: &CStr) -> io::Result<Entry> {
        name_validation::validate_name(name)?;
        let name_bytes = name.to_bytes();
        if name_bytes == b"." {
            let path = self.path_of(parent)?;
            let attr = self.provider.getattr(&path)?;
            let node = self.intern_and_reference(path);
            return Ok(self.build_entry(node.inode, &attr));
        }
        let child = self.child_path(parent, name)?;
        let attr = self.provider.getattr(&child)?;
        Ok(self.intern_entry(child, &attr))
    }

    pub(crate) fn do_getattr(&self, ino: u64) -> io::Result<(stat64, Duration)> {
        let path = self.path_of(ino)?;
        let attr = self.provider.getattr(&path)?;
        Ok((vattr_to_stat(ino, &attr), self.cfg.attr_timeout))
    }

    pub(crate) fn do_setattr(
        &self,
        ino: u64,
        attr: stat64,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        let path = self.path_of(ino)?;
        // Start from current attributes, overlay the requested fields.
        let mut target = self.provider.getattr(&path)?;

        if valid.contains(SetattrValid::SIZE) {
            if attr.st_size < 0 {
                return Err(platform::einval());
            }
            target.size = attr.st_size as u64;
        }
        if valid.contains(SetattrValid::MODE) {
            // st_mode is u16 on macOS, u32 on linux/windows.
            #[allow(clippy::unnecessary_cast)]
            {
                target.mode = (attr.st_mode as u32) & 0o7777;
            }
        }
        if valid.contains(SetattrValid::UID) {
            target.uid = attr.st_uid;
        }
        if valid.contains(SetattrValid::GID) {
            target.gid = attr.st_gid;
        }
        if valid.contains(SetattrValid::ATIME) {
            target.atime = Some(if valid.contains(SetattrValid::ATIME_NOW) {
                SystemTime::now()
            } else {
                systime(attr.st_atime, attr.st_atime_nsec)
            });
        }
        if valid.contains(SetattrValid::MTIME) {
            target.mtime = Some(if valid.contains(SetattrValid::MTIME_NOW) {
                SystemTime::now()
            } else {
                systime(attr.st_mtime, attr.st_mtime_nsec)
            });
        }
        if valid.contains(SetattrValid::CTIME) {
            target.ctime = Some(systime(attr.st_ctime, attr.st_ctime_nsec));
        }

        let result = self.provider.setattr(&path, &target, valid)?;
        Ok((vattr_to_stat(ino, &result), self.cfg.attr_timeout))
    }

    pub(crate) fn do_readlink(&self, ino: u64) -> io::Result<Vec<u8>> {
        let path = self.path_of(ino)?;
        let target = self.provider.readlink(&path)?;
        name_validation::validate_symlink_target_bytes(&target)?;
        Ok(target)
    }

    pub(crate) fn do_access(&self, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
        // Permission check uses the caller's uid and primary gid only.
        let path = self.path_of(ino)?;
        let attr = self.provider.getattr(&path)?;

        if mask == platform::ACCESS_F_OK {
            return Ok(());
        }
        let perm = attr.mode & 0o7777;
        if ctx.uid == 0 {
            if mask & platform::ACCESS_X_OK != 0 && perm & 0o111 == 0 {
                return Err(platform::eacces());
            }
            return Ok(());
        }
        let bits = if attr.uid == ctx.uid {
            (perm >> 6) & 0o7
        } else if attr.gid == ctx.gid {
            (perm >> 3) & 0o7
        } else {
            perm & 0o7
        };
        if mask & platform::ACCESS_R_OK != 0 && bits & 0o4 == 0 {
            return Err(platform::eacces());
        }
        if mask & platform::ACCESS_W_OK != 0 && bits & 0o2 == 0 {
            return Err(platform::eacces());
        }
        if mask & platform::ACCESS_X_OK != 0 && bits & 0o1 == 0 {
            return Err(platform::eacces());
        }
        Ok(())
    }
}
