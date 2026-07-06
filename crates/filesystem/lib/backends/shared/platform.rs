//! Platform abstractions for filesystem backends.
//!
//! Provides errno translation (macOS → Linux), stat wrappers, and error helpers.
//!
//! ## Errno Translation
//!
//! The FUSE protocol always expects Linux errno values. On Linux, errors pass through
//! unchanged. On macOS, BSD errno values are mapped to their Linux equivalents via
//! `linux_error()`. All filesystem operations must wrap OS errors with `linux_error()`
//! before returning them through the FUSE interface.
//!
//! ## RESOLVE_BENEATH
//!
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` (Linux 5.6+)
//! provides kernel-enforced path containment that blocks `..` traversal, symlink traversal,
//! procfs-style magic links, and concurrent rename races atomically. Availability is probed
//! at init time and cached in `PassthroughFs::has_openat2`. Falls back to `openat(O_NOFOLLOW)`
//! on older kernels.

#![cfg_attr(any(target_os = "linux", windows), allow(dead_code))]

use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;

#[cfg(unix)]
use crate::{SetattrValid, stat64};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const LINUX_EPERM: i32 = 1;
pub(crate) const LINUX_ENOENT: i32 = 2;
pub(crate) const LINUX_ESRCH: i32 = 3;
pub(crate) const LINUX_EINTR: i32 = 4;
pub(crate) const LINUX_EIO: i32 = 5;
pub(crate) const LINUX_ENXIO: i32 = 6;
pub(crate) const LINUX_ENOEXEC: i32 = 8;
pub(crate) const LINUX_EBADF: i32 = 9;
pub(crate) const LINUX_ECHILD: i32 = 10;
pub(crate) const LINUX_EAGAIN: i32 = 11;
pub(crate) const LINUX_ENOMEM: i32 = 12;
pub(crate) const LINUX_EACCES: i32 = 13;
pub(crate) const LINUX_EFAULT: i32 = 14;
pub(crate) const LINUX_ENOTBLK: i32 = 15;
pub(crate) const LINUX_EBUSY: i32 = 16;
pub(crate) const LINUX_EEXIST: i32 = 17;
pub(crate) const LINUX_EXDEV: i32 = 18;
pub(crate) const LINUX_ENODEV: i32 = 19;
pub(crate) const LINUX_ENOTDIR: i32 = 20;
pub(crate) const LINUX_EISDIR: i32 = 21;
pub(crate) const LINUX_EINVAL: i32 = 22;
pub(crate) const LINUX_ENFILE: i32 = 23;
pub(crate) const LINUX_EMFILE: i32 = 24;
pub(crate) const LINUX_ENOTTY: i32 = 25;
pub(crate) const LINUX_ETXTBSY: i32 = 26;
pub(crate) const LINUX_EFBIG: i32 = 27;
pub(crate) const LINUX_ENOSPC: i32 = 28;
pub(crate) const LINUX_ESPIPE: i32 = 29;
pub(crate) const LINUX_EROFS: i32 = 30;
pub(crate) const LINUX_EMLINK: i32 = 31;
pub(crate) const LINUX_EPIPE: i32 = 32;
pub(crate) const LINUX_EDOM: i32 = 33;
pub(crate) const LINUX_ERANGE: i32 = 34;
pub(crate) const LINUX_EDEADLK: i32 = 35;
pub(crate) const LINUX_ENAMETOOLONG: i32 = 36;
pub(crate) const LINUX_ENOLCK: i32 = 37;
pub(crate) const LINUX_ENOSYS: i32 = 38;
pub(crate) const LINUX_ENOTEMPTY: i32 = 39;
pub(crate) const LINUX_ELOOP: i32 = 40;
pub(crate) const LINUX_ENOMSG: i32 = 42;
pub(crate) const LINUX_EIDRM: i32 = 43;
pub(crate) const LINUX_ENOSTR: i32 = 60;
pub(crate) const LINUX_ENODATA: i32 = 61;
pub(crate) const LINUX_ETIME: i32 = 62;
pub(crate) const LINUX_ENOSR: i32 = 63;
pub(crate) const LINUX_EREMOTE: i32 = 66;
pub(crate) const LINUX_ENOLINK: i32 = 67;
pub(crate) const LINUX_EPROTO: i32 = 71;
pub(crate) const LINUX_EMULTIHOP: i32 = 72;
pub(crate) const LINUX_EBADMSG: i32 = 74;
pub(crate) const LINUX_EOVERFLOW: i32 = 75;
pub(crate) const LINUX_EILSEQ: i32 = 84;
pub(crate) const LINUX_EUSERS: i32 = 87;
pub(crate) const LINUX_ENOTSOCK: i32 = 88;
pub(crate) const LINUX_EDESTADDRREQ: i32 = 89;
pub(crate) const LINUX_EMSGSIZE: i32 = 90;
pub(crate) const LINUX_EPROTOTYPE: i32 = 91;
pub(crate) const LINUX_ENOPROTOOPT: i32 = 92;
pub(crate) const LINUX_EPROTONOSUPPORT: i32 = 93;
pub(crate) const LINUX_ESOCKTNOSUPPORT: i32 = 94;
pub(crate) const LINUX_EOPNOTSUPP: i32 = 95;
pub(crate) const LINUX_EPFNOSUPPORT: i32 = 96;
pub(crate) const LINUX_EAFNOSUPPORT: i32 = 97;
pub(crate) const LINUX_EADDRINUSE: i32 = 98;
pub(crate) const LINUX_EADDRNOTAVAIL: i32 = 99;
pub(crate) const LINUX_ENETDOWN: i32 = 100;
pub(crate) const LINUX_ENETUNREACH: i32 = 101;
pub(crate) const LINUX_ENETRESET: i32 = 102;
pub(crate) const LINUX_ECONNABORTED: i32 = 103;
pub(crate) const LINUX_ECONNRESET: i32 = 104;
pub(crate) const LINUX_ENOBUFS: i32 = 105;
pub(crate) const LINUX_EISCONN: i32 = 106;
pub(crate) const LINUX_ENOTCONN: i32 = 107;
pub(crate) const LINUX_ESHUTDOWN: i32 = 108;
pub(crate) const LINUX_ETOOMANYREFS: i32 = 109;
pub(crate) const LINUX_ETIMEDOUT: i32 = 110;
pub(crate) const LINUX_ECONNREFUSED: i32 = 111;
pub(crate) const LINUX_EHOSTDOWN: i32 = 112;
pub(crate) const LINUX_EHOSTUNREACH: i32 = 113;
pub(crate) const LINUX_EALREADY: i32 = 114;
pub(crate) const LINUX_EINPROGRESS: i32 = 115;
pub(crate) const LINUX_ESTALE: i32 = 116;
pub(crate) const LINUX_EDQUOT: i32 = 122;
pub(crate) const LINUX_ECANCELED: i32 = 125;
pub(crate) const LINUX_EOWNERDEAD: i32 = 130;
pub(crate) const LINUX_ENOTRECOVERABLE: i32 = 131;

// Mode/dirent/access constants use the **Linux** wire values as plain
// literals rather than host libc constants: the FUSE guest is always Linux, so
// these are protocol values, not host values. (On Linux and macOS the libc
// constants happen to coincide with these; on Windows several — S_IFLNK,
// every DT_* — do not exist in libc at all.)
pub(crate) const MODE_TYPE_MASK: u32 = 0o170000;

pub(crate) const MODE_REG: u32 = 0o100000;

pub(crate) const MODE_DIR: u32 = 0o040000;

pub(crate) const MODE_LNK: u32 = 0o120000;

pub(crate) const MODE_CHR: u32 = 0o020000;

pub(crate) const MODE_BLK: u32 = 0o060000;

pub(crate) const MODE_FIFO: u32 = 0o010000;

pub(crate) const MODE_SOCK: u32 = 0o140000;

pub(crate) const MODE_SETUID: u32 = 0o4000;

pub(crate) const MODE_SETGID: u32 = 0o2000;

pub(crate) const DIRENT_REG: u32 = 8;

pub(crate) const DIRENT_DIR: u32 = 4;

pub(crate) const DIRENT_LNK: u32 = 10;

pub(crate) const DIRENT_CHR: u32 = 2;

pub(crate) const DIRENT_BLK: u32 = 6;

pub(crate) const DIRENT_FIFO: u32 = 1;

pub(crate) const DIRENT_SOCK: u32 = 12;

pub(crate) const ACCESS_F_OK: u32 = 0;

pub(crate) const ACCESS_R_OK: u32 = 4;

pub(crate) const ACCESS_W_OK: u32 = 2;

pub(crate) const ACCESS_X_OK: u32 = 1;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a utimens-compatible timespec array from a FUSE setattr request.
#[cfg(unix)]
pub(crate) fn build_timespecs(attr: stat64, valid: SetattrValid) -> [libc::timespec; 2] {
    let mut times = [libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_OMIT,
    }; 2];

    if valid.contains(SetattrValid::ATIME) {
        if valid.contains(SetattrValid::ATIME_NOW) {
            times[0].tv_nsec = libc::UTIME_NOW;
        } else {
            times[0].tv_sec = attr.st_atime;
            times[0].tv_nsec = attr.st_atime_nsec;
        }
    }

    if valid.contains(SetattrValid::MTIME) {
        if valid.contains(SetattrValid::MTIME_NOW) {
            times[1].tv_nsec = libc::UTIME_NOW;
        } else {
            times[1].tv_sec = attr.st_mtime;
            times[1].tv_nsec = attr.st_mtime_nsec;
        }
    }

    times
}

/// Translate a native OS error to a Linux errno value.
///
/// On Linux this is an identity function. On macOS, BSD errno values are
/// mapped to their Linux equivalents, since the FUSE protocol always
/// expects Linux errno values.
#[cfg(target_os = "linux")]
pub(crate) fn linux_error(error: io::Error) -> io::Error {
    error
}

/// Translate a native OS error to a Linux errno value.
#[cfg(target_os = "macos")]
pub(crate) fn linux_error(error: io::Error) -> io::Error {
    io::Error::from_raw_os_error(linux_errno_raw(error.raw_os_error().unwrap_or(libc::EIO)))
}

/// Win32 error codes recognized by the Windows [`linux_error`] mapping.
#[cfg(windows)]
mod win32 {
    pub(super) const ERROR_FILE_NOT_FOUND: i32 = 2;
    pub(super) const ERROR_PATH_NOT_FOUND: i32 = 3;
    pub(super) const ERROR_ACCESS_DENIED: i32 = 5;
    pub(super) const ERROR_NOT_SAME_DEVICE: i32 = 17;
    pub(super) const ERROR_SHARING_VIOLATION: i32 = 32;
    pub(super) const ERROR_FILE_EXISTS: i32 = 80;
    pub(super) const ERROR_INVALID_NAME: i32 = 123;
    pub(super) const ERROR_DIR_NOT_EMPTY: i32 = 145;
    pub(super) const ERROR_ALREADY_EXISTS: i32 = 183;
    pub(super) const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
}

/// Translate a native OS error to a Linux errno value.
///
/// Windows raw os errors are Win32 codes, not errnos: map the codes the
/// filesystem backends actually encounter, then fall back to
/// [`io::ErrorKind`], then to `EIO`. This is the single Windows→Linux error
/// mapping in the crate — the Windows passthrough backend delegates here.
#[cfg(windows)]
pub(crate) fn linux_error(error: io::Error) -> io::Error {
    use win32::*;
    let errno = match error.raw_os_error() {
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => LINUX_ENOENT,
        Some(ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD) => LINUX_EACCES,
        Some(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) => LINUX_EEXIST,
        Some(ERROR_DIR_NOT_EMPTY) => LINUX_ENOTEMPTY,
        Some(ERROR_SHARING_VIOLATION) => LINUX_EBUSY,
        Some(ERROR_INVALID_NAME) => LINUX_EINVAL,
        Some(ERROR_NOT_SAME_DEVICE) => LINUX_EXDEV,
        _ => match error.kind() {
            io::ErrorKind::NotFound => LINUX_ENOENT,
            io::ErrorKind::PermissionDenied => LINUX_EACCES,
            io::ErrorKind::AlreadyExists => LINUX_EEXIST,
            io::ErrorKind::InvalidInput => LINUX_EINVAL,
            io::ErrorKind::Unsupported => LINUX_EOPNOTSUPP,
            _ => LINUX_EIO,
        },
    };
    io::Error::from_raw_os_error(errno)
}

/// Map a native errno to its Linux equivalent.
#[cfg(target_os = "macos")]
fn linux_errno_raw(errno: i32) -> i32 {
    match errno {
        libc::EPERM => LINUX_EPERM,
        libc::ENOENT => LINUX_ENOENT,
        libc::ESRCH => LINUX_ESRCH,
        libc::EINTR => LINUX_EINTR,
        libc::EIO => LINUX_EIO,
        libc::ENXIO => LINUX_ENXIO,
        libc::ENOEXEC => LINUX_ENOEXEC,
        libc::EBADF => LINUX_EBADF,
        libc::ECHILD => LINUX_ECHILD,
        libc::EDEADLK => LINUX_EDEADLK,
        libc::ENOMEM => LINUX_ENOMEM,
        libc::EACCES => LINUX_EACCES,
        libc::EFAULT => LINUX_EFAULT,
        libc::ENOTBLK => LINUX_ENOTBLK,
        libc::EBUSY => LINUX_EBUSY,
        libc::EEXIST => LINUX_EEXIST,
        libc::EXDEV => LINUX_EXDEV,
        libc::ENODEV => LINUX_ENODEV,
        libc::ENOTDIR => LINUX_ENOTDIR,
        libc::EISDIR => LINUX_EISDIR,
        libc::EINVAL => LINUX_EINVAL,
        libc::ENFILE => LINUX_ENFILE,
        libc::EMFILE => LINUX_EMFILE,
        libc::ENOTTY => LINUX_ENOTTY,
        libc::ETXTBSY => LINUX_ETXTBSY,
        libc::EFBIG => LINUX_EFBIG,
        libc::ENOSPC => LINUX_ENOSPC,
        libc::ESPIPE => LINUX_ESPIPE,
        libc::EROFS => LINUX_EROFS,
        libc::EMLINK => LINUX_EMLINK,
        libc::EPIPE => LINUX_EPIPE,
        libc::EDOM => LINUX_EDOM,
        libc::EAGAIN => LINUX_EAGAIN,
        libc::EINPROGRESS => LINUX_EINPROGRESS,
        libc::EALREADY => LINUX_EALREADY,
        libc::ENOTSOCK => LINUX_ENOTSOCK,
        libc::EDESTADDRREQ => LINUX_EDESTADDRREQ,
        libc::EMSGSIZE => LINUX_EMSGSIZE,
        libc::EPROTOTYPE => LINUX_EPROTOTYPE,
        libc::ENOPROTOOPT => LINUX_ENOPROTOOPT,
        libc::EPROTONOSUPPORT => LINUX_EPROTONOSUPPORT,
        libc::ESOCKTNOSUPPORT => LINUX_ESOCKTNOSUPPORT,
        libc::EPFNOSUPPORT => LINUX_EPFNOSUPPORT,
        libc::EAFNOSUPPORT => LINUX_EAFNOSUPPORT,
        libc::EADDRINUSE => LINUX_EADDRINUSE,
        libc::EADDRNOTAVAIL => LINUX_EADDRNOTAVAIL,
        libc::ENETDOWN => LINUX_ENETDOWN,
        libc::ENETUNREACH => LINUX_ENETUNREACH,
        libc::ENETRESET => LINUX_ENETRESET,
        libc::ECONNABORTED => LINUX_ECONNABORTED,
        libc::ECONNRESET => LINUX_ECONNRESET,
        libc::ENOBUFS => LINUX_ENOBUFS,
        libc::EISCONN => LINUX_EISCONN,
        libc::ENOTCONN => LINUX_ENOTCONN,
        libc::ESHUTDOWN => LINUX_ESHUTDOWN,
        libc::ETOOMANYREFS => LINUX_ETOOMANYREFS,
        libc::ETIMEDOUT => LINUX_ETIMEDOUT,
        libc::ECONNREFUSED => LINUX_ECONNREFUSED,
        libc::ELOOP => LINUX_ELOOP,
        libc::ENAMETOOLONG => LINUX_ENAMETOOLONG,
        libc::EHOSTDOWN => LINUX_EHOSTDOWN,
        libc::EHOSTUNREACH => LINUX_EHOSTUNREACH,
        libc::ENOTEMPTY => LINUX_ENOTEMPTY,
        libc::EUSERS => LINUX_EUSERS,
        libc::EDQUOT => LINUX_EDQUOT,
        libc::ESTALE => LINUX_ESTALE,
        libc::EREMOTE => LINUX_EREMOTE,
        libc::ENOLCK => LINUX_ENOLCK,
        libc::ENOSYS => LINUX_ENOSYS,
        libc::EOVERFLOW => LINUX_EOVERFLOW,
        libc::ECANCELED => LINUX_ECANCELED,
        libc::EIDRM => LINUX_EIDRM,
        libc::ENOMSG => LINUX_ENOMSG,
        libc::EILSEQ => LINUX_EILSEQ,
        libc::ENOATTR => LINUX_ENODATA,
        libc::EBADMSG => LINUX_EBADMSG,
        libc::EMULTIHOP => LINUX_EMULTIHOP,
        libc::ENODATA => LINUX_ENODATA,
        libc::ENOLINK => LINUX_ENOLINK,
        libc::ENOSR => LINUX_ENOSR,
        libc::ENOSTR => LINUX_ENOSTR,
        libc::EPROTO => LINUX_EPROTO,
        libc::ETIME => LINUX_ETIME,
        libc::EOPNOTSUPP => LINUX_EOPNOTSUPP,
        libc::ENOTRECOVERABLE => LINUX_ENOTRECOVERABLE,
        libc::EOWNERDEAD => LINUX_EOWNERDEAD,
        _ => LINUX_EIO,
    }
}

/// Create an `io::Error` with Linux `EIO`.
pub(crate) fn eio() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EIO)
}

/// Create an `io::Error` with Linux `EBADF`.
pub(crate) fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EBADF)
}

/// Create an `io::Error` with Linux `EINVAL`.
pub(crate) fn einval() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EINVAL)
}

/// Create an `io::Error` with Linux `EACCES`.
pub(crate) fn eacces() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EACCES)
}

/// Create an `io::Error` with Linux `EPERM`.
pub(crate) fn eperm() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EPERM)
}

/// Create an `io::Error` with Linux `EROFS`.
pub(crate) fn erofs() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EROFS)
}

/// Create an `io::Error` with Linux `ENOSYS`.
pub(crate) fn enosys() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENOSYS)
}

/// Create an `io::Error` with Linux `ENOENT`.
pub(crate) fn enoent() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENOENT)
}

/// Create an `io::Error` with Linux `ENODATA`.
pub(crate) fn enodata() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENODATA)
}

/// Create an `io::Error` with Linux `EISDIR`.
pub(crate) fn eisdir() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EISDIR)
}

/// Create an `io::Error` with Linux `ENOTDIR`.
pub(crate) fn enotdir() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENOTDIR)
}

/// Create an `io::Error` with Linux `ENOTEMPTY`.
pub(crate) fn enotempty() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENOTEMPTY)
}

/// Create an `io::Error` with Linux `ELOOP`.
pub(crate) fn eloop() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ELOOP)
}

/// Create an `io::Error` with Linux `ENAMETOOLONG`.
pub(crate) fn enametoolong() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENAMETOOLONG)
}

/// Create an `io::Error` with Linux `EEXIST`.
pub(crate) fn eexist() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EEXIST)
}

/// Create an `io::Error` with Linux `ENOSPC`.
pub(crate) fn enospc() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENOSPC)
}

/// Create an `io::Error` with Linux `EFBIG`.
pub(crate) fn efbig() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EFBIG)
}

/// Create an `io::Error` with Linux `EOPNOTSUPP`.
pub(crate) fn eopnotsupp() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EOPNOTSUPP)
}

/// Create an `io::Error` with Linux `ENODEV`.
pub(crate) fn enodev() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENODEV)
}

/// Create an `io::Error` with Linux `ENXIO`.
pub(crate) fn enxio() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ENXIO)
}

/// Create an `io::Error` with Linux `ERANGE`.
pub(crate) fn erange() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ERANGE)
}

/// Create an `io::Error` with Linux `EAGAIN`.
pub(crate) fn eagain() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EAGAIN)
}

/// Create an `io::Error` with Linux `ESTALE`.
pub(crate) fn estale() -> io::Error {
    io::Error::from_raw_os_error(LINUX_ESTALE)
}

/// Map a provider [`io::Error`] to a Linux wire errno for RPC responses.
///
/// A [`PathFs`](crate::backends::vfs::PathFs) provider reports errors in
/// **Linux** errno — the value carried on the wire and surfaced to the guest —
/// exactly as the Go SDK requires of its providers. The reference
/// implementations, the trait defaults, the RPC path/name validators, and the
/// `platform::*` helpers all construct Linux wire values, so the wire errno is
/// the provider's errno verbatim and no host→Linux translation happens here on
/// any platform.
///
/// Resist re-adding a value-based BSD→Linux translation: the Linux and BSD
/// numbering spaces overlap (e.g. Linux `ENODATA`=61 == BSD `ECONNREFUSED`=61,
/// Linux `EAGAIN`=11 == BSD `EDEADLK`=11), so any translation keyed on the raw
/// integer alone silently mistranslates one source to satisfy the other. A
/// provider that performs raw host syscalls on a non-Linux dev host is itself
/// responsible for translating their result to Linux errno (e.g. via
/// [`linux_error`]), just as the Go SDK is.
pub(crate) fn provider_errno_to_wire(error: io::Error) -> i32 {
    error.raw_os_error().unwrap_or(LINUX_EIO)
}

/// Call `fstat` on a raw file descriptor and return a `stat64`.
#[cfg(unix)]
pub(crate) fn fstat(fd: RawFd) -> io::Result<stat64> {
    let mut st = unsafe { std::mem::zeroed::<stat64>() };

    #[cfg(target_os = "linux")]
    let ret = unsafe { libc::fstat64(fd, &mut st) };

    #[cfg(target_os = "macos")]
    let ret = unsafe { libc::fstat(fd, &mut st) };

    if ret < 0 {
        Err(linux_error(io::Error::last_os_error()))
    } else {
        Ok(st)
    }
}

/// Normalize a mode value to `u32` across platforms.
#[cfg(target_os = "linux")]
pub(crate) fn mode_u32(mode: libc::mode_t) -> u32 {
    mode
}

/// Normalize a mode value to `u32` across platforms.
#[cfg(target_os = "macos")]
pub(crate) fn mode_u32(mode: libc::mode_t) -> u32 {
    mode as u32
}

/// Extract the file type bits from a mode value.
#[cfg(unix)]
pub(crate) fn mode_file_type(mode: libc::mode_t) -> u32 {
    mode_u32(mode) & MODE_TYPE_MASK
}

/// Convert a file type bitmask to a dirent type value.
pub(crate) fn dirent_type_from_mode(file_type: u32) -> u32 {
    match file_type {
        MODE_LNK => DIRENT_LNK,
        MODE_DIR => DIRENT_DIR,
        MODE_CHR => DIRENT_CHR,
        MODE_BLK => DIRENT_BLK,
        MODE_FIFO => DIRENT_FIFO,
        MODE_SOCK => DIRENT_SOCK,
        _ => DIRENT_REG,
    }
}

/// Normalize `st_ino` to `u64` across platforms.
#[cfg(unix)]
pub(crate) fn stat_ino(st: &stat64) -> u64 {
    st.st_ino
}

/// Normalize `st_dev` to `u64` across platforms.
#[cfg(target_os = "linux")]
pub(crate) fn stat_dev(st: &stat64) -> u64 {
    st.st_dev
}

/// Normalize `st_dev` to `u64` across platforms.
#[cfg(target_os = "macos")]
pub(crate) fn stat_dev(st: &stat64) -> u64 {
    st.st_dev as u64
}

/// Read the target of a symlink opened by file descriptor (Linux only).
///
/// This uses `readlinkat(fd, "", ...)` so the kernel reads the symlink target
/// referenced by the already-pinned fd itself. Using `/proc/self/fd/N` here
/// would instead expose the procfs magic-link target and leak a host path.
#[cfg(target_os = "linux")]
pub(crate) fn readlink_fd(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let len = unsafe {
        libc::readlinkat(
            fd,
            c"".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if len < 0 {
        Err(linux_error(io::Error::last_os_error()))
    } else {
        buf.truncate(len as usize);
        Ok(buf)
    }
}

/// Struct for the `openat2` syscall (Linux 5.6+).
#[cfg(target_os = "linux")]
#[repr(C)]
pub(crate) struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// `RESOLVE_BENEATH` flag — prevent path resolution from escaping the directory tree.
#[cfg(target_os = "linux")]
pub(crate) const RESOLVE_BENEATH: u64 = 0x08;

/// `RESOLVE_NO_SYMLINKS` flag — reject all symlink traversal during resolution.
#[cfg(target_os = "linux")]
pub(crate) const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// `RESOLVE_NO_MAGICLINKS` flag — reject procfs-style magic links.
#[cfg(target_os = "linux")]
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[cfg(target_os = "linux")]
const OPENAT2_RESOLVE_FLAGS: u64 = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;

#[cfg(target_os = "linux")]
const LINUX_OPEN_FLAG_MASK: i32 = libc::O_APPEND
    | libc::O_CREAT
    | libc::O_EXCL
    | libc::O_NOCTTY
    | libc::O_TRUNC
    | libc::O_NONBLOCK
    | libc::O_DSYNC
    | libc::O_SYNC
    | libc::O_ASYNC
    | libc::O_DIRECT
    | libc::O_LARGEFILE
    | libc::O_DIRECTORY
    | libc::O_NOFOLLOW
    | libc::O_NOATIME
    | libc::O_CLOEXEC
    | libc::O_PATH
    | libc::O_TMPFILE;

/// Syscall number for `openat2` (same on x86_64 and aarch64).
#[cfg(target_os = "linux")]
const SYS_OPENAT2: libc::c_long = 437;

/// Probe whether the `openat2` syscall is available (Linux 5.6+).
///
/// Attempts a minimal openat2 call on the current directory. Returns `true`
/// if the syscall succeeds or returns any error other than `ENOSYS`.
#[cfg(target_os = "linux")]
pub(crate) fn probe_openat2() -> bool {
    let how = OpenHow {
        flags: libc::O_CLOEXEC as u64 | libc::O_PATH as u64,
        mode: 0,
        resolve: OPENAT2_RESOLVE_FLAGS,
    };
    let ret = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            libc::AT_FDCWD,
            c".".as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if ret >= 0 {
        unsafe { libc::close(ret as i32) };
        true
    } else {
        !matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL)
        )
    }
}

/// Open a file relative to a directory with Linux openat2 containment if available.
///
/// Falls back to regular `openat` if `openat2` is not available.
#[cfg(target_os = "linux")]
pub(crate) fn open_beneath(
    dirfd: RawFd,
    name: *const libc::c_char,
    flags: i32,
    use_openat2: bool,
) -> RawFd {
    if use_openat2 {
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: OPENAT2_RESOLVE_FLAGS,
        };
        let ret = unsafe {
            libc::syscall(
                SYS_OPENAT2,
                dirfd,
                name,
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            ) as i32
        };
        if ret >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
            return ret;
        }
        // ENOSYS fallthrough to regular openat.
    }
    unsafe { libc::openat(dirfd, name, flags | libc::O_CLOEXEC) }
}

#[cfg(target_os = "linux")]
pub(crate) fn sanitize_linux_open_flags(flags: i32) -> i32 {
    (flags & libc::O_ACCMODE) | (flags & LINUX_OPEN_FLAG_MASK)
}

/// Convert a `libc::statx` struct to a `stat64` struct (Linux only).
///
/// Used in the lookup collapse optimization where `statx` with `AT_EMPTY_PATH`
/// provides both stat data and `mnt_id` in a single syscall.
#[cfg(target_os = "linux")]
pub(crate) fn statx_to_stat64(stx: &libc::statx) -> stat64 {
    let mut st: stat64 = unsafe { std::mem::zeroed() };
    st.st_dev = makedev(stx.stx_dev_major, stx.stx_dev_minor);
    st.st_ino = stx.stx_ino;
    st.st_nlink = stx.stx_nlink as _;
    st.st_mode = stx.stx_mode as _;
    st.st_uid = stx.stx_uid;
    st.st_gid = stx.stx_gid;
    st.st_rdev = makedev(stx.stx_rdev_major, stx.stx_rdev_minor);
    st.st_size = stx.stx_size as _;
    st.st_blksize = stx.stx_blksize as _;
    st.st_blocks = stx.stx_blocks as _;
    st.st_atime = stx.stx_atime.tv_sec;
    st.st_atime_nsec = stx.stx_atime.tv_nsec as _;
    st.st_mtime = stx.stx_mtime.tv_sec;
    st.st_mtime_nsec = stx.stx_mtime.tv_nsec as _;
    st.st_ctime = stx.stx_ctime.tv_sec;
    st.st_ctime_nsec = stx.stx_ctime.tv_nsec as _;
    st
}

/// Compute a `dev_t` from major and minor numbers (Linux glibc formula).
#[cfg(target_os = "linux")]
fn makedev(major: u32, minor: u32) -> u64 {
    ((major as u64 & 0xfffff000) << 32)
        | ((major as u64 & 0x00000fff) << 8)
        | ((minor as u64 & 0xffffff00) << 12)
        | (minor as u64 & 0x000000ff)
}

/// Call `fstatat` (no follow) on a name relative to a directory fd.
#[cfg(unix)]
pub(crate) fn fstatat_nofollow(dirfd: RawFd, name: &std::ffi::CStr) -> io::Result<stat64> {
    let mut st = unsafe { std::mem::zeroed::<stat64>() };

    #[cfg(target_os = "linux")]
    let ret = unsafe { libc::fstatat64(dirfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };

    #[cfg(target_os = "macos")]
    let ret = unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };

    if ret < 0 {
        Err(linux_error(io::Error::last_os_error()))
    } else {
        Ok(st)
    }
}
