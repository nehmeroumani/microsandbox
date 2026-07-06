package vfs

// Server-side dispatch: turn a decoded [request] into [PathFs] calls and encode
// the reply. Mirrors the Rust `rpc::dispatch` module. The [Serve] loop drives
// this one request at a time per connection, so directory removal (kind check +
// delete) cannot race a concurrent create on the same connection.

const maxIOSize uint32 = 128 * 1024

// Linux renameat2 flags.
const (
	renameNoreplace  uint32 = 1
	renameExchange   uint32 = 2
	knownRenameFlags        = renameNoreplace | renameExchange
)

// knownSetattrValid is the set of setattr `valid` bits the runtime understands,
// mirroring msb_krun's SetattrValid (MODE|UID|GID|SIZE|ATIME|MTIME|ATIME_NOW|
// MTIME_NOW|CTIME|KILL_SUIDGID). The Rust server applies
// SetattrValid::from_bits_truncate before calling the provider; masking here
// keeps the Go provider from seeing bits the Rust provider never would.
const knownSetattrValid uint32 = 1 | 2 | 4 | 8 | 16 | 32 | 128 | 256 | 1024 | 2048

// dispatch answers one request, encoding any error as an Err response with its
// Linux errno.
func dispatch(p PathFs, req *request) []byte {
	payload, err := dispatchInner(p, req)
	if err != nil {
		return respErr(errnoOf(err))
	}
	return payload
}

func dispatchInner(p PathFs, req *request) ([]byte, error) {
	if err := validateRequestPaths(req); err != nil {
		return nil, err
	}
	switch req.Op {
	case "GetAttr":
		a, err := p.GetAttr(req.Path)
		if err != nil {
			return nil, err
		}
		return respAttr(a), nil

	case "GetAttrMany":
		results := make([]attrResult, len(req.Paths))
		for i, path := range req.Paths {
			a, err := p.GetAttr(path)
			if err != nil {
				// Per-path errors are reported in-band.
				results[i] = attrResult{errno: errnoOf(err)}
			} else {
				results[i] = attrResult{attr: a}
			}
		}
		return respAttrMany(results), nil

	case "ReadDir":
		entries, err := p.ReadDir(req.Path)
		if err != nil {
			return nil, err
		}
		if len(entries) > maxReaddirEntries {
			return nil, EINVAL
		}
		return respDir(entries), nil

	case "ReadLink":
		target, err := p.ReadLink(req.Path)
		if err != nil {
			return nil, err
		}
		if err := validateSymlinkTarget(target); err != nil {
			return nil, err
		}
		return respBytes(target), nil

	case "Read":
		if req.Size > maxIOSize {
			return nil, EINVAL
		}
		data, err := p.Read(req.Path, req.Offset, req.Size)
		if err != nil {
			return nil, err
		}
		if uint32(len(data)) > req.Size {
			return nil, EIO
		}
		return respBytes(data), nil

	case "Write":
		if uint32(len(req.Data)) > maxIOSize {
			return nil, EINVAL
		}
		n, err := p.Write(req.Path, req.Offset, req.Data)
		if err != nil {
			return nil, err
		}
		if n > len(req.Data) {
			return nil, EIO
		}
		return respCount(uint64(n)), nil

	case "Create":
		a, err := p.Create(req.Path, req.Attr)
		if err != nil {
			return nil, err
		}
		return respAttr(a), nil

	case "Mkdir":
		a, err := p.Mkdir(req.Path, req.Mode)
		if err != nil {
			return nil, err
		}
		return respAttr(a), nil

	case "Remove":
		// Route directory removal through Rmdir; everything else through Remove.
		attr, err := p.GetAttr(req.Path)
		switch {
		case err == nil && attr.Kind == Dir:
			if e := p.Rmdir(req.Path); e != nil {
				return nil, e
			}
		case err != nil && errnoOf(err) != int32(ENOENT):
			return nil, err
		default:
			if e := p.Remove(req.Path); e != nil {
				return nil, e
			}
		}
		return respOk(), nil

	case "Rename":
		if req.Flags&^knownRenameFlags != 0 {
			return nil, EINVAL
		}
		if req.Flags&renameNoreplace != 0 && req.Flags&renameExchange != 0 {
			return nil, EINVAL
		}
		if req.Flags&renameExchange != 0 {
			return nil, ENOSYS
		}
		if err := p.Rename(req.From, req.To, req.Flags); err != nil {
			return nil, err
		}
		return respOk(), nil

	case "SetAttr":
		a, err := p.SetAttr(req.Path, req.Attr, req.Valid&knownSetattrValid)
		if err != nil {
			return nil, err
		}
		return respAttr(a), nil

	case "Symlink":
		a, err := p.Symlink(req.Path, req.Target)
		if err != nil {
			return nil, err
		}
		return respAttr(a), nil

	case "SetXattr":
		if err := p.SetXattr(req.Path, req.Name, req.Value, req.Flags); err != nil {
			return nil, err
		}
		return respOk(), nil

	case "GetXattr":
		v, err := p.GetXattr(req.Path, req.Name)
		if err != nil {
			return nil, err
		}
		return respBytes(v), nil

	case "ListXattr":
		names, err := p.ListXattr(req.Path)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			if err := validateXattrName(name); err != nil {
				return nil, err
			}
		}
		return respNames(names), nil

	case "RemoveXattr":
		if err := p.RemoveXattr(req.Path, req.Name); err != nil {
			return nil, err
		}
		return respOk(), nil

	case "Flush":
		if err := p.Flush(req.Path); err != nil {
			return nil, err
		}
		return respOk(), nil

	case "Fsync":
		if err := p.Fsync(req.Path, req.Datasync); err != nil {
			return nil, err
		}
		return respOk(), nil

	case "FsyncDir":
		if err := p.FsyncDir(req.Path); err != nil {
			return nil, err
		}
		return respOk(), nil

	case "StatFs":
		s, err := p.StatFs()
		if err != nil {
			return nil, err
		}
		return respStatFs(s), nil

	default:
		return nil, EINVAL
	}
}

// validateRequestPaths rejects guest paths/names/targets the provider must not
// be asked to serve, before any provider call.
func validateRequestPaths(req *request) error {
	switch req.Op {
	case "GetAttr", "ReadDir", "ReadLink", "Read", "Write", "Create", "Mkdir",
		"Remove", "SetAttr", "ListXattr", "Flush", "Fsync", "FsyncDir":
		return validateProviderPath(req.Path)
	case "SetXattr", "GetXattr", "RemoveXattr":
		if err := validateProviderPath(req.Path); err != nil {
			return err
		}
		return validateXattrName(req.Name)
	case "GetAttrMany":
		for _, path := range req.Paths {
			if err := validateProviderPath(path); err != nil {
				return err
			}
		}
		return nil
	case "Rename":
		if err := validateProviderPath(req.From); err != nil {
			return err
		}
		return validateProviderPath(req.To)
	case "Symlink":
		if err := validateProviderPath(req.Path); err != nil {
			return err
		}
		return validateSymlinkTarget(req.Target)
	case "StatFs":
		return nil
	default:
		return EINVAL
	}
}
