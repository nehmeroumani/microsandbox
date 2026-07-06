// Package vfs implements the controlling-process half of a microsandbox virtual
// mount: a path-addressed [PathFs] provider and the [Serve] loop that answers
// the VFS RPC protocol the `msb` runtime issues from inside the sandbox.
//
// The runtime serves FUSE in a separate process, so the provider cannot be a set
// of in-process callbacks; it runs here and replies over a socket. The wire
// protocol mirrors the Rust `microsandbox_filesystem::backends::vfs::rpc` server
// byte-for-byte (see wire_vectors_test.go).
package vfs

import "time"

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

// NodeKind is the kind of a filesystem node.
type NodeKind uint8

// Node kinds, matching the wire byte values.
const (
	File NodeKind = iota
	Dir
	Symlink
	Char
	Block
	Fifo
	Socket
)

// Attr is the portable attribute shape a provider reports for a node. A nil
// timestamp means "current time"; a nil Nlink lets the scaffold default it.
type Attr struct {
	Kind  NodeKind
	Mode  uint32
	Size  uint64
	Uid   uint32
	Gid   uint32
	Nlink *uint64
	Rdev  uint32
	Atime *time.Time
	Mtime *time.Time
	Ctime *time.Time
}

// FileAttr is a convenience constructor for a regular-file attr.
func FileAttr(mode uint32, size uint64) Attr {
	return Attr{Kind: File, Mode: mode, Size: size}
}

// DirAttr is a convenience constructor for a directory attr.
func DirAttr(mode uint32) Attr {
	return Attr{Kind: Dir, Mode: mode}
}

// DirEntry is one child returned by [PathFs.ReadDir] (excluding "."/".." which
// the scaffold synthesizes).
type DirEntry struct {
	Name []byte
	Kind NodeKind
}

// StatFs reports filesystem statistics.
type StatFs struct {
	Bsize   uint64
	Frsize  uint64
	Blocks  uint64
	Bfree   uint64
	Bavail  uint64
	Files   uint64
	Ffree   uint64
	Namemax uint64
}

// PathFs is a path-addressed filesystem backend. All paths are absolute, begin
// with "/", and are raw bytes (never assumed UTF-8). Implementations must be
// safe for the concurrency model of [Serve] (one request at a time per
// connection). Embed [ReadOnly] to get ENOSYS defaults for every mutating
// method and implement only what you need.
type PathFs interface {
	GetAttr(path []byte) (Attr, error)
	ReadDir(path []byte) ([]DirEntry, error)
	Read(path []byte, offset uint64, size uint32) ([]byte, error)

	Write(path []byte, offset uint64, data []byte) (int, error)
	Create(path []byte, attr Attr) (Attr, error)
	Mkdir(path []byte, mode uint32) (Attr, error)
	Remove(path []byte) error
	Rmdir(path []byte) error
	Rename(from, to []byte, flags uint32) error
	SetAttr(path []byte, attr Attr, valid uint32) (Attr, error)
	Symlink(path, target []byte) (Attr, error)
	ReadLink(path []byte) ([]byte, error)

	SetXattr(path, name, value []byte, flags uint32) error
	GetXattr(path, name []byte) ([]byte, error)
	ListXattr(path []byte) ([][]byte, error)
	RemoveXattr(path, name []byte) error

	Flush(path []byte) error
	Fsync(path []byte, datasync bool) error
	FsyncDir(path []byte) error
	StatFs() (StatFs, error)
}

//--------------------------------------------------------------------------------------------------
// ReadOnly base
//--------------------------------------------------------------------------------------------------

// ReadOnly provides ENOSYS implementations of every mutating [PathFs] method
// plus no-op durability and a generic StatFs. Embed it and override
// GetAttr/ReadDir/Read (and any writes you support):
//
//	type MyFs struct{ vfs.ReadOnly }
//	func (MyFs) GetAttr(path []byte) (vfs.Attr, error) { ... }
type ReadOnly struct{}

func (ReadOnly) GetAttr([]byte) (Attr, error)                  { return Attr{}, ENOSYS }
func (ReadOnly) ReadDir([]byte) ([]DirEntry, error)            { return nil, ENOSYS }
func (ReadOnly) Read([]byte, uint64, uint32) ([]byte, error)   { return nil, ENOSYS }
func (ReadOnly) Write([]byte, uint64, []byte) (int, error)     { return 0, ENOSYS }
func (ReadOnly) Create([]byte, Attr) (Attr, error)             { return Attr{}, ENOSYS }
func (ReadOnly) Mkdir([]byte, uint32) (Attr, error)            { return Attr{}, ENOSYS }
func (ReadOnly) Remove([]byte) error                           { return ENOSYS }
func (ReadOnly) Rmdir([]byte) error                            { return ENOSYS }
func (ReadOnly) Rename([]byte, []byte, uint32) error           { return ENOSYS }
func (ReadOnly) SetAttr([]byte, Attr, uint32) (Attr, error)    { return Attr{}, ENOSYS }
func (ReadOnly) Symlink([]byte, []byte) (Attr, error)          { return Attr{}, ENOSYS }
func (ReadOnly) ReadLink([]byte) ([]byte, error)               { return nil, ENOSYS }
func (ReadOnly) SetXattr([]byte, []byte, []byte, uint32) error { return ENOSYS }
func (ReadOnly) GetXattr([]byte, []byte) ([]byte, error)       { return nil, ENOSYS }
func (ReadOnly) ListXattr([]byte) ([][]byte, error)            { return nil, nil }
func (ReadOnly) RemoveXattr([]byte, []byte) error              { return ENOSYS }
func (ReadOnly) Flush([]byte) error                            { return nil }
func (ReadOnly) Fsync([]byte, bool) error                      { return nil }
func (ReadOnly) FsyncDir([]byte) error                         { return nil }

// StatFs reports a generic, effectively-unbounded volume.
func (ReadOnly) StatFs() (StatFs, error) {
	return StatFs{Bsize: 4096, Frsize: 4096, Namemax: 255}, nil
}
