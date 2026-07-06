package vfs

// The VFS-op wire protocol, mirroring the Rust
// `microsandbox_filesystem::backends::vfs::rpc::protocol` module byte-for-byte.
//
// Requests/responses are CBOR with serde's external enum tagging: a unit
// variant (e.g. `StatFs`, `Ok`) encodes as a bare text string; every other
// variant encodes as a single-entry map `{Variant: payload}`. Structs encode as
// definite maps with field-name keys in declaration order. Paths and names are
// raw byte strings; errors carry a Linux errno.

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const protocolVersion uint32 = 1

const maxFrameLen uint32 = 8 << 20

// Wire-protocol limits, mirroring the Rust `rpc::protocol` constants. The Go
// server enforces them in validateRequestLimits so it rejects the same oversized
// requests the Rust server does, instead of forwarding unbounded work to the
// provider.
const (
	maxBatchPaths     = 4096
	maxBatchPathBytes = 256 * 1024
	maxReaddirEntries = 1 << 20
	maxXattrValue     = 64 * 1024
)

var helloMagic = [4]byte{'M', 'V', 'F', 'S'}

//--------------------------------------------------------------------------------------------------
// Request
//--------------------------------------------------------------------------------------------------

// request is the decoded form of a VfsRequest. `Op` is the variant name; only
// the fields that variant carries are populated.
type request struct {
	Op       string
	Path     []byte
	Paths    [][]byte
	Name     []byte
	Target   []byte
	Value    []byte
	Data     []byte
	From     []byte
	To       []byte
	Offset   uint64
	Size     uint32
	Mode     uint32
	Flags    uint32
	Valid    uint32
	Datasync bool
	Attr     Attr
}

// decodeRequest parses one CBOR-encoded VfsRequest.
func decodeRequest(data []byte) (*request, error) {
	if len(data) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	r := newCborReader(data)
	// A unit variant is a bare text string; everything else is a 1-entry map.
	if data[0]>>5 == majText {
		op, err := r.readText()
		if err != nil {
			return nil, err
		}
		if op == "StatFs" {
			return &request{Op: op}, nil
		}
		return nil, fmt.Errorf("vfs: unknown request %q", op)
	}

	n, err := r.readMapHeader()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, fmt.Errorf("vfs: request map must have one entry, got %d", n)
	}
	op, err := r.readText()
	if err != nil {
		return nil, err
	}
	req := &request{Op: op}
	if err := req.readFields(r); err != nil {
		return nil, err
	}
	if err := validateRequestLimits(req); err != nil {
		return nil, err
	}
	return req, nil
}

// validateRequestLimits rejects requests whose declared sizes exceed protocol
// limits, mirroring the Rust `validate_request_limits`. Symlink targets over the
// cap report ENAMETOOLONG; the rest report EINVAL.
func validateRequestLimits(req *request) error {
	switch req.Op {
	case "GetAttrMany":
		if len(req.Paths) > maxBatchPaths {
			return EINVAL
		}
		total := 0
		for _, p := range req.Paths {
			total += len(p)
		}
		if total > maxBatchPathBytes {
			return EINVAL
		}
	case "Read":
		if req.Size > maxIOSize {
			return EINVAL
		}
	case "Write":
		if len(req.Data) > int(maxIOSize) {
			return EINVAL
		}
	case "Symlink":
		if len(req.Target) > maxSymlinkTarget {
			return ENAMETOOLONG
		}
	case "SetXattr":
		if len(req.Value) > maxXattrValue {
			return EINVAL
		}
	}
	return nil
}

// readFields reads the variant's inner field map. Field names are unique across
// variants, so one reader serves them all; `Op` selects which are meaningful.
func (req *request) readFields(r *cborReader) error {
	n, err := r.readMapHeader()
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		key, err := r.readText()
		if err != nil {
			return err
		}
		switch key {
		case "path":
			req.Path, err = r.readBytes()
		case "paths":
			req.Paths, err = readByteArray(r)
		case "name":
			req.Name, err = r.readBytes()
		case "target":
			req.Target, err = r.readBytes()
		case "value":
			req.Value, err = r.readBytes()
		case "data":
			req.Data, err = r.readBytes()
		case "from":
			req.From, err = r.readBytes()
		case "to":
			req.To, err = r.readBytes()
		case "offset":
			req.Offset, err = r.readUint()
		case "size":
			req.Size, err = r.readU32()
		case "mode":
			req.Mode, err = r.readU32()
		case "flags":
			req.Flags, err = r.readU32()
		case "valid":
			req.Valid, err = r.readU32()
		case "datasync":
			req.Datasync, err = r.readBool()
		case "attr":
			req.Attr, err = decodeAttr(r)
		default:
			return fmt.Errorf("vfs: unknown request field %q", key)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func readByteArray(r *cborReader) ([][]byte, error) {
	n, err := r.readArrayHeader()
	if err != nil {
		return nil, err
	}
	// Each element occupies at least one byte on the wire, so a header that
	// declares more entries than remain in the buffer is corrupt. Bound the
	// allocation by the remaining bytes before make, so a tiny frame with a huge
	// array-length prefix cannot force a multi-gigabyte allocation.
	if n < 0 || n > r.remaining() {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		if out[i], err = r.readBytes(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

//--------------------------------------------------------------------------------------------------
// Attr <-> wire
//--------------------------------------------------------------------------------------------------

func encodeAttr(w *cborWriter, a Attr) {
	w.mapHeader(10)
	w.text("kind")
	w.uint(uint64(a.Kind))
	w.text("mode")
	w.uint(uint64(a.Mode))
	w.text("size")
	w.uint(a.Size)
	w.text("uid")
	w.uint(uint64(a.Uid))
	w.text("gid")
	w.uint(uint64(a.Gid))
	w.text("nlink")
	if a.Nlink == nil {
		w.null()
	} else {
		w.uint(*a.Nlink)
	}
	w.text("rdev")
	w.uint(uint64(a.Rdev))
	w.text("atime")
	encodeOptTime(w, a.Atime)
	w.text("mtime")
	encodeOptTime(w, a.Mtime)
	w.text("ctime")
	encodeOptTime(w, a.Ctime)
}

// encodeOptTime writes null or a `[sec, nsec]` array using the same floor
// convention as the Rust codec (sec = floor seconds, nsec in [0, 1e9)).
func encodeOptTime(w *cborWriter, t *time.Time) {
	if t == nil {
		w.null()
		return
	}
	w.arrayHeader(2)
	w.int(t.Unix())
	w.uint(uint64(uint32(t.Nanosecond())))
}

func decodeAttr(r *cborReader) (Attr, error) {
	n, err := r.readMapHeader()
	if err != nil {
		return Attr{}, err
	}
	var a Attr
	for i := 0; i < n; i++ {
		key, err := r.readText()
		if err != nil {
			return Attr{}, err
		}
		switch key {
		case "kind":
			v, e := r.readUint()
			if e == nil && v > uint64(Socket) {
				return Attr{}, fmt.Errorf("vfs: unknown node kind %d", v)
			}
			a.Kind, err = NodeKind(v), e
		case "mode":
			a.Mode, err = r.readU32()
		case "size":
			a.Size, err = r.readUint()
		case "uid":
			a.Uid, err = r.readU32()
		case "gid":
			a.Gid, err = r.readU32()
		case "nlink":
			if !r.tryNull() {
				v, e := r.readUint()
				a.Nlink, err = &v, e
			}
		case "rdev":
			a.Rdev, err = r.readU32()
		case "atime":
			a.Atime, err = decodeOptTime(r)
		case "mtime":
			a.Mtime, err = decodeOptTime(r)
		case "ctime":
			a.Ctime, err = decodeOptTime(r)
		default:
			return Attr{}, fmt.Errorf("vfs: unknown attr field %q", key)
		}
		if err != nil {
			return Attr{}, err
		}
	}
	return a, nil
}

func decodeOptTime(r *cborReader) (*time.Time, error) {
	if r.tryNull() {
		return nil, nil
	}
	n, err := r.readArrayHeader()
	if err != nil {
		return nil, err
	}
	if n != 2 {
		return nil, fmt.Errorf("vfs: time tuple must have 2 elements, got %d", n)
	}
	sec, err := r.readInt()
	if err != nil {
		return nil, err
	}
	nsec, err := r.readUint()
	if err != nil {
		return nil, err
	}
	t := time.Unix(sec, int64(nsec)).UTC()
	return &t, nil
}

//--------------------------------------------------------------------------------------------------
// Response encoders
//--------------------------------------------------------------------------------------------------

func respAttr(a Attr) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("Attr")
	encodeAttr(w, a)
	return w.buf
}

func respDir(entries []DirEntry) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("Dir")
	w.arrayHeader(len(entries))
	for _, e := range entries {
		w.mapHeader(2)
		w.text("name")
		w.bytes(e.Name)
		w.text("kind")
		w.uint(uint64(e.Kind))
	}
	return w.buf
}

func respBytes(b []byte) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("Bytes")
	w.bytes(b)
	return w.buf
}

func respNames(names [][]byte) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("Names")
	w.arrayHeader(len(names))
	for _, n := range names {
		w.bytes(n)
	}
	return w.buf
}

func respCount(n uint64) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("Count")
	w.uint(n)
	return w.buf
}

func respStatFs(s StatFs) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("StatFs")
	w.mapHeader(8)
	for _, kv := range []struct {
		k string
		v uint64
	}{
		{"bsize", s.Bsize}, {"frsize", s.Frsize}, {"blocks", s.Blocks},
		{"bfree", s.Bfree}, {"bavail", s.Bavail}, {"files", s.Files},
		{"ffree", s.Ffree}, {"namemax", s.Namemax},
	} {
		w.text(kv.k)
		w.uint(kv.v)
	}
	return w.buf
}

// attrResult is one entry of an AttrMany batch: attributes or a Linux errno.
type attrResult struct {
	attr  Attr
	errno int32 // 0 => ok
}

func respAttrMany(results []attrResult) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("AttrMany")
	w.arrayHeader(len(results))
	for _, res := range results {
		w.mapHeader(1)
		if res.errno == 0 {
			w.text("Ok")
			encodeAttr(w, res.attr)
		} else {
			w.text("Err")
			w.int(int64(res.errno))
		}
	}
	return w.buf
}

func respOk() []byte {
	w := &cborWriter{}
	w.text("Ok")
	return w.buf
}

func respErr(errno int32) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("Err")
	w.int(int64(errno))
	return w.buf
}

//--------------------------------------------------------------------------------------------------
// Hello + framing
//--------------------------------------------------------------------------------------------------

func writeHello(w io.Writer) error {
	var buf [8]byte
	copy(buf[:4], helloMagic[:])
	binary.BigEndian.PutUint32(buf[4:], protocolVersion)
	_, err := w.Write(buf[:])
	return err
}

func readHello(r io.Reader) (uint32, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	if [4]byte(buf[:4]) != helloMagic {
		return 0, fmt.Errorf("vfs: bad protocol magic")
	}
	version := binary.BigEndian.Uint32(buf[4:])
	if version != protocolVersion {
		return 0, fmt.Errorf("vfs: unsupported protocol version %d (supported %d)", version, protocolVersion)
	}
	return version, nil
}

func writeFrame(w io.Writer, id uint64, payload []byte) error {
	if uint64(len(payload)) > uint64(maxFrameLen) {
		return fmt.Errorf("vfs: frame too large")
	}
	var head [12]byte
	binary.BigEndian.PutUint32(head[:4], uint32(len(payload)))
	binary.BigEndian.PutUint64(head[4:], id)
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) (id uint64, payload []byte, err error) {
	var head [12]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[:4])
	if n > maxFrameLen {
		return 0, nil, fmt.Errorf("vfs: frame too large")
	}
	id = binary.BigEndian.Uint64(head[4:])
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return id, payload, nil
}
