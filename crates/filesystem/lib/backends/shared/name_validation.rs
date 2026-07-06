//! Name validation for filesystem operations.
//!
//! Every operation that accepts a guest-provided directory entry name must
//! call [`validate_name`] to prevent path traversal attacks.

use std::{ffi::CStr, io};

use super::platform;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate a directory entry name, blocking traversal attacks.
///
/// Rejects: empty names, `..`, and names containing `/`.
///
/// Backslash is intentionally allowed — it is a valid filename character on
/// Linux. The filesystem operates on raw bytes, not path-separator-aware
/// strings.
pub(crate) fn validate_name(name: &CStr) -> io::Result<()> {
    let bytes = name.to_bytes();

    if bytes.is_empty() {
        return Err(platform::einval());
    }
    if bytes == b".." {
        return Err(platform::eperm());
    }
    if bytes.contains(&b'/') {
        return Err(platform::eperm());
    }

    Ok(())
}

/// Maximum allowed component length (NAME_MAX on Linux).
const NAME_MAX: usize = 255;

/// Validate a directory entry name for in-memory filesystem operations.
///
/// Extends [`validate_name`] with rejection of:
/// - `.` (would alias the directory itself)
/// - Names longer than `NAME_MAX` (255 bytes)
pub(crate) fn validate_memfs_name(name: &CStr) -> io::Result<()> {
    validate_name(name)?;

    let bytes = name.to_bytes();

    if bytes == b"." {
        return Err(platform::eperm());
    }
    if bytes.len() > NAME_MAX {
        return Err(platform::enametoolong());
    }

    Ok(())
}

/// Maximum absolute path length (PATH_MAX on Linux).
const PATH_MAX: usize = 4096;

/// Maximum symlink target length accepted on the wire.
const MAX_SYMLINK_TARGET: usize = 4096;

/// Validate a directory entry name returned by a provider's `readdir`.
///
/// Rejects empty names, `.`, `..`, names containing `/` or NUL, and names
/// longer than `NAME_MAX`. The scaffold synthesizes `.`/`..` itself.
pub(crate) fn validate_readdir_name(name: &[u8]) -> io::Result<()> {
    if name.is_empty() || name == b"." || name == b".." {
        return Err(platform::eperm());
    }
    if name.contains(&b'/') || name.contains(&0) {
        return Err(platform::einval());
    }
    if name.len() > NAME_MAX {
        return Err(platform::enametoolong());
    }
    Ok(())
}

/// Validate an absolute guest path on the virtual-filesystem RPC wire.
///
/// Rejects relative paths, NUL bytes, `.`/`..` components, empty components,
/// and paths or components that exceed Linux `PATH_MAX`/`NAME_MAX`.
pub(crate) fn validate_provider_path_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes[0] != b'/' {
        return Err(platform::einval());
    }
    if bytes.len() > PATH_MAX {
        return Err(platform::enametoolong());
    }
    if bytes.contains(&0) {
        return Err(platform::einval());
    }
    if bytes.len() == 1 {
        return Ok(());
    }
    for component in bytes[1..].split(|&b| b == b'/') {
        if component.is_empty() {
            return Err(platform::einval());
        }
        validate_readdir_name(component)?;
    }
    Ok(())
}

/// Validate a symlink target before passing it to a provider.
///
/// Rejects NUL bytes, absolute targets, `..` path components, and over-long
/// targets that could confuse naive resolution if mishandled.
pub(crate) fn validate_symlink_target_bytes(bytes: &[u8]) -> io::Result<()> {
    // An empty target is invalid (POSIX `symlink(2)` returns ENOENT); reject it
    // rather than create/return a symlink that resolves to nothing.
    if bytes.is_empty() {
        return Err(platform::einval());
    }
    if bytes.len() > MAX_SYMLINK_TARGET {
        return Err(platform::enametoolong());
    }
    if bytes.contains(&0) {
        return Err(platform::einval());
    }
    if bytes.first() == Some(&b'/') {
        return Err(platform::eperm());
    }
    for component in bytes.split(|&b| b == b'/') {
        if component == b".." {
            return Err(platform::eperm());
        }
    }
    Ok(())
}

/// Validate an extended-attribute name before passing it to a provider.
///
/// Rejects empty names, NUL bytes, `/`, and names longer than `NAME_MAX`.
pub(crate) fn validate_xattr_name_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(platform::einval());
    }
    if bytes.contains(&0) || bytes.contains(&b'/') {
        return Err(platform::einval());
    }
    if bytes.len() > NAME_MAX {
        return Err(platform::enametoolong());
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cstr(s: &[u8]) -> CString {
        CString::new(s.to_vec()).unwrap()
    }

    #[test]
    fn validate_name_accepts_normal() {
        assert!(validate_name(&cstr(b"hello.txt")).is_ok());
        assert!(validate_name(&cstr(b".hidden")).is_ok());
        assert!(validate_name(&cstr(b".")).is_ok()); // validate_name allows "." (overlay rejects it)
    }

    #[test]
    fn validate_name_rejects_empty() {
        let name = c"";
        assert!(validate_name(name).is_err());
    }

    #[test]
    fn validate_name_rejects_dotdot() {
        assert!(validate_name(&cstr(b"..")).is_err());
    }

    #[test]
    fn validate_name_rejects_slash() {
        assert!(validate_name(&cstr(b"a/b")).is_err());
    }

    #[test]
    fn validate_name_allows_backslash() {
        assert!(validate_name(&cstr(b"a\\b")).is_ok());
    }

    #[test]
    fn validate_symlink_target_rejects_empty() {
        assert!(validate_symlink_target_bytes(b"").is_err());
        assert!(validate_symlink_target_bytes(b"ok/target").is_ok());
    }

    #[test]
    fn validate_provider_path_rejects_over_path_max() {
        // Each component is <= NAME_MAX, so this fails on total PATH_MAX, not
        // component length.
        let mut path = Vec::new();
        for _ in 0..30 {
            path.push(b'/');
            path.extend(std::iter::repeat_n(b'a', 200));
        }
        assert!(path.len() > PATH_MAX);
        assert!(validate_provider_path_bytes(&path).is_err());
    }
}
