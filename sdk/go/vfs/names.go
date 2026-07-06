package vfs

import "bytes"

// Path/name validators mirroring the Rust `shared::name_validation` rules, so
// the Go server rejects the same guest-supplied paths, names, and symlink
// targets with the same Linux errno.

const (
	nameMax          = 255
	pathMax          = 4096
	maxSymlinkTarget = 4096
)

// validateReaddirName rejects empty, ".", "..", names with "/" or NUL, and
// names longer than NAME_MAX.
func validateReaddirName(name []byte) error {
	if len(name) == 0 || bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
		return EPERM
	}
	if bytes.IndexByte(name, '/') >= 0 || bytes.IndexByte(name, 0) >= 0 {
		return EINVAL
	}
	if len(name) > nameMax {
		return ENAMETOOLONG
	}
	return nil
}

// validateProviderPath rejects relative paths, NUL bytes, empty/"."/".."
// components, and paths/components over PATH_MAX/NAME_MAX.
func validateProviderPath(p []byte) error {
	if len(p) == 0 || p[0] != '/' {
		return EINVAL
	}
	if len(p) > pathMax {
		return ENAMETOOLONG
	}
	if bytes.IndexByte(p, 0) >= 0 {
		return EINVAL
	}
	if len(p) == 1 {
		return nil
	}
	for _, comp := range bytes.Split(p[1:], []byte("/")) {
		if len(comp) == 0 {
			return EINVAL
		}
		if err := validateReaddirName(comp); err != nil {
			return err
		}
	}
	return nil
}

// validateXattrName rejects empty names, NUL, "/", and names over NAME_MAX.
func validateXattrName(name []byte) error {
	if len(name) == 0 {
		return EINVAL
	}
	if bytes.IndexByte(name, 0) >= 0 || bytes.IndexByte(name, '/') >= 0 {
		return EINVAL
	}
	if len(name) > nameMax {
		return ENAMETOOLONG
	}
	return nil
}

// validateSymlinkTarget rejects empty/over-long targets, NUL, absolute targets,
// and ".." components.
func validateSymlinkTarget(target []byte) error {
	if len(target) == 0 {
		return EINVAL
	}
	if len(target) > maxSymlinkTarget {
		return ENAMETOOLONG
	}
	if bytes.IndexByte(target, 0) >= 0 {
		return EINVAL
	}
	if target[0] == '/' {
		return EPERM
	}
	for _, comp := range bytes.Split(target, []byte("/")) {
		if bytes.Equal(comp, []byte("..")) {
			return EPERM
		}
	}
	return nil
}
