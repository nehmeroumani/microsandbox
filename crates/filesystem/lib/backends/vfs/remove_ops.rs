//! Removal and rename operations for [`VirtualFs`](super::VirtualFs): unlink,
//! rmdir, and rename.

use std::ffi::CStr;
use std::io;

use super::*;
use crate::backends::shared::{name_validation, platform};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    pub(crate) fn do_unlink(&self, parent: u64, name: &CStr) -> io::Result<()> {
        let child = self.child_path(parent, name)?;
        let attr = self.provider.getattr(&child)?;
        if attr.kind == NodeKind::Dir {
            return Err(platform::eisdir());
        }
        self.provider.remove(&child)?;
        self.invalidate_path(&child);
        self.invalidate_dir_listings(&[parent_path(&child)]);
        Ok(())
    }

    pub(crate) fn do_rmdir(&self, parent: u64, name: &CStr) -> io::Result<()> {
        let child = self.child_path(parent, name)?;
        self.provider.rmdir(&child)?;
        self.invalidate_dir_listings(&[child.clone(), parent_path(&child)]);
        self.invalidate_path(&child);
        Ok(())
    }

    pub(crate) fn do_rename(
        &self,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        if flags & !KNOWN_RENAME_FLAGS != 0 {
            return Err(platform::einval());
        }
        if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
            return Err(platform::einval());
        }
        if flags & RENAME_EXCHANGE != 0 {
            return Err(platform::enosys());
        }

        name_validation::validate_memfs_name(oldname)?;
        name_validation::validate_memfs_name(newname)?;
        let from = join(&self.path_of(olddir)?, oldname.to_bytes());
        let to = join(&self.path_of(newdir)?, newname.to_bytes());
        name_validation::validate_provider_path_bytes(&from)?;
        name_validation::validate_provider_path_bytes(&to)?;
        if from == to {
            return Ok(());
        }
        if is_at_or_under(&to, &from) {
            return Err(platform::einval());
        }
        self.provider.rename_with_flags(&from, &to, flags)?;
        let mut inodes = self.inodes.write().unwrap();
        remap_subtree_inodes(&mut inodes, &from, &to);
        drop(inodes);
        self.invalidate_after_rename(&from, &to);
        Ok(())
    }
}
