package vfs

import "fmt"

// Errno is a Linux errno returned by a [PathFs] provider. The wire protocol and
// the guest both speak Linux errno, so providers construct errors directly from
// these constants — no host→Linux translation is needed (unlike the Rust
// provider path on macOS hosts).
type Errno int32

// Error implements the error interface.
func (e Errno) Error() string {
	return fmt.Sprintf("vfs: errno %d", int32(e))
}

// Linux errno values used across the protocol.
const (
	EPERM        Errno = 1
	ENOENT       Errno = 2
	EIO          Errno = 5
	ENXIO        Errno = 6
	EBADF        Errno = 9
	EAGAIN       Errno = 11
	EACCES       Errno = 13
	EEXIST       Errno = 17
	ENOTDIR      Errno = 20
	EISDIR       Errno = 21
	EINVAL       Errno = 22
	EFBIG        Errno = 27
	ERANGE       Errno = 34
	ENAMETOOLONG Errno = 36
	ENOSYS       Errno = 38
	ENOTEMPTY    Errno = 39
	ELOOP        Errno = 40
	ENODATA      Errno = 61
	EOPNOTSUPP   Errno = 95
	ESTALE       Errno = 116
)

// errnoOr extracts the Linux errno an error should surface to the guest as,
// reporting fallback for plain (non-[Errno]) errors. The two policies in this
// package: provider errors fall back to EIO ([errnoOf]); request decode errors
// fall back to EINVAL (mirroring the Rust server's decode_error_errno).
func errnoOr(err error, fallback Errno) int32 {
	if err == nil {
		return 0
	}
	if e, ok := err.(Errno); ok {
		return int32(e)
	}
	return int32(fallback)
}

// errnoOf extracts the Linux errno for a provider error; plain errors are EIO.
func errnoOf(err error) int32 {
	return errnoOr(err, EIO)
}
