//! Node-creation operations for [`VirtualFs`](super::VirtualFs): symlink,
//! mknod, and mkdir. (Regular-file creation lives in `file_ops` because it
//! returns an open handle.)

use std::ffi::CStr;
use std::io;

use super::*;
use crate::Entry;
use crate::backends::shared::{name_validation, platform};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    pub(crate) fn do_symlink(
        &self,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
    ) -> io::Result<Entry> {
        let child = self.child_path(parent, name)?;
        name_validation::validate_symlink_target_bytes(linkname.to_bytes())?;
        let attr = self.provider.symlink(&child, linkname.to_bytes())?;
        self.invalidate_dir_listings(&[parent_path(&child)]);
        Ok(self.intern_entry(child, &attr))
    }

    pub(crate) fn do_mknod(
        &self,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let child = self.child_path(parent, name)?;
        let Some(kind) = NodeKind::from_mode(mode) else {
            return Err(platform::einval());
        };
        let mut attr = VAttr::new(kind, (mode & 0o7777) & !(umask & 0o7777), 0);
        attr.rdev = rdev;
        let attr = self.provider.create(&child, &attr)?;
        self.invalidate_dir_listings(&[parent_path(&child)]);
        Ok(self.intern_entry(child, &attr))
    }

    pub(crate) fn do_mkdir(
        &self,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        let child = self.child_path(parent, name)?;
        let attr = self
            .provider
            .mkdir(&child, (mode & 0o7777) & !(umask & 0o7777))?;
        self.invalidate_dir_listings(&[parent_path(&child)]);
        Ok(self.intern_entry(child, &attr))
    }
}
