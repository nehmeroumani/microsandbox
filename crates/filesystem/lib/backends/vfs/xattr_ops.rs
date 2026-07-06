//! Extended-attribute operations for [`VirtualFs`](super::VirtualFs): setxattr,
//! getxattr, listxattr, and removexattr.

use std::ffi::CStr;
use std::io;

use super::*;
use crate::backends::shared::{name_validation, platform};
use crate::{GetxattrReply, ListxattrReply};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    pub(crate) fn do_setxattr(
        &self,
        ino: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        let path = self.path_of(ino)?;
        let name = name.to_bytes();
        name_validation::validate_xattr_name_bytes(name)?;

        // Enforce XATTR_CREATE/REPLACE semantics against the provider's view.
        // Only a genuine ENODATA means "absent".
        if flags & (XATTR_CREATE | XATTR_REPLACE) != 0 {
            let exists = match self.provider.getxattr(&path, name) {
                Ok(_) => true,
                Err(e) if e.raw_os_error() == platform::enodata().raw_os_error() => false,
                Err(e) => return Err(e),
            };
            if flags & XATTR_CREATE != 0 && exists {
                return Err(platform::eexist());
            }
            if flags & XATTR_REPLACE != 0 && !exists {
                return Err(platform::enodata());
            }
        }

        self.provider.setxattr(&path, name, value, flags)
    }

    pub(crate) fn do_getxattr(
        &self,
        ino: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        let path = self.path_of(ino)?;
        let name = name.to_bytes();
        name_validation::validate_xattr_name_bytes(name)?;
        let value = self.provider.getxattr(&path, name)?;
        if size == 0 {
            Ok(GetxattrReply::Count(value.len() as u32))
        } else if value.len() > size as usize {
            Err(platform::erange())
        } else {
            Ok(GetxattrReply::Value(value))
        }
    }

    pub(crate) fn do_listxattr(&self, ino: u64, size: u32) -> io::Result<ListxattrReply> {
        let path = self.path_of(ino)?;
        let names = self.provider.listxattr(&path)?;

        let mut buf = Vec::new();
        for name in names {
            name_validation::validate_xattr_name_bytes(&name)?;
            buf.extend_from_slice(&name);
            buf.push(0);
        }

        if size == 0 {
            Ok(ListxattrReply::Count(buf.len() as u32))
        } else if buf.len() > size as usize {
            Err(platform::erange())
        } else {
            Ok(ListxattrReply::Names(buf))
        }
    }

    pub(crate) fn do_removexattr(&self, ino: u64, name: &CStr) -> io::Result<()> {
        let path = self.path_of(ino)?;
        let name = name.to_bytes();
        name_validation::validate_xattr_name_bytes(name)?;
        self.provider.removexattr(&path, name)
    }
}
