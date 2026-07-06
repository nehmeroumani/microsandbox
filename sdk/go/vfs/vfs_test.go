package vfs

import (
	"bytes"
	"net"
	"sort"
	"testing"
	"time"
)

//--------------------------------------------------------------------------------------------------
// Attr round-trip (exercises nlink + the timestamp floor convention)
//--------------------------------------------------------------------------------------------------

func TestAttrRoundTripWithTimesAndNlink(t *testing.T) {
	nlink := uint64(3)
	atime := time.Unix(1000, 500_000_000).UTC()
	// A pre-epoch instant exercises the floor convention (sec=-1, nsec=5e8).
	mtime := time.Unix(0, 0).Add(-500 * time.Millisecond).UTC()
	in := Attr{
		Kind: Symlink, Mode: 0o777, Size: 9, Uid: 7, Gid: 8,
		Nlink: &nlink, Rdev: 42, Atime: &atime, Mtime: &mtime,
	}
	w := &cborWriter{}
	encodeAttr(w, in)

	out, err := decodeAttr(newCborReader(w.buf))
	if err != nil {
		t.Fatalf("decodeAttr: %v", err)
	}
	if out.Kind != in.Kind || out.Mode != in.Mode || out.Size != in.Size ||
		out.Uid != in.Uid || out.Gid != in.Gid || out.Rdev != in.Rdev {
		t.Fatalf("scalar mismatch: %+v vs %+v", out, in)
	}
	if out.Nlink == nil || *out.Nlink != nlink {
		t.Fatalf("nlink: got %v", out.Nlink)
	}
	if out.Atime == nil || !out.Atime.Equal(atime) {
		t.Fatalf("atime: got %v want %v", out.Atime, atime)
	}
	if out.Mtime == nil || !out.Mtime.Equal(mtime) {
		t.Fatalf("mtime: got %v want %v", out.Mtime, mtime)
	}
	if out.Ctime != nil {
		t.Fatalf("ctime should be nil, got %v", out.Ctime)
	}
}

//--------------------------------------------------------------------------------------------------
// In-memory provider for the end-to-end serve test
//--------------------------------------------------------------------------------------------------

type memNode struct {
	kind NodeKind
	data []byte
}

type memFS struct {
	ReadOnly
	m map[string]*memNode
}

func newMemFS() *memFS {
	return &memFS{m: map[string]*memNode{"/": {kind: Dir}}}
}

func parentOf(p string) string {
	i := bytes.LastIndexByte([]byte(p), '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func baseOf(p string) string {
	i := bytes.LastIndexByte([]byte(p), '/')
	return p[i+1:]
}

func (f *memFS) GetAttr(path []byte) (Attr, error) {
	n, ok := f.m[string(path)]
	if !ok {
		return Attr{}, ENOENT
	}
	if n.kind == Dir {
		return DirAttr(0o755), nil
	}
	return FileAttr(0o644, uint64(len(n.data))), nil
}

func (f *memFS) ReadDir(path []byte) ([]DirEntry, error) {
	k := string(path)
	if _, ok := f.m[k]; !ok {
		return nil, ENOENT
	}
	var out []DirEntry
	for p, n := range f.m {
		if p != k && parentOf(p) == k {
			out = append(out, DirEntry{Name: []byte(baseOf(p)), Kind: n.kind})
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].Name) < string(out[j].Name) })
	return out, nil
}

func (f *memFS) Read(path []byte, offset uint64, size uint32) ([]byte, error) {
	n, ok := f.m[string(path)]
	if !ok {
		return nil, ENOENT
	}
	if offset >= uint64(len(n.data)) {
		return nil, nil
	}
	end := min(offset+uint64(size), uint64(len(n.data)))
	return append([]byte(nil), n.data[offset:end]...), nil
}

func (f *memFS) Create(path []byte, attr Attr) (Attr, error) {
	f.m[string(path)] = &memNode{kind: File}
	return FileAttr(attr.Mode, 0), nil
}

func (f *memFS) Write(path []byte, offset uint64, data []byte) (int, error) {
	n, ok := f.m[string(path)]
	if !ok {
		return 0, ENOENT
	}
	end := int(offset) + len(data)
	if end > len(n.data) {
		n.data = append(n.data, make([]byte, end-len(n.data))...)
	}
	copy(n.data[offset:], data)
	return len(data), nil
}

func (f *memFS) Remove(path []byte) error {
	if _, ok := f.m[string(path)]; !ok {
		return ENOENT
	}
	delete(f.m, string(path))
	return nil
}

//--------------------------------------------------------------------------------------------------
// Request frame builders (test-side client)
//--------------------------------------------------------------------------------------------------

func reqUnit(op string) []byte {
	w := &cborWriter{}
	w.text(op)
	return w.buf
}

func reqOp(op string, fields func(w *cborWriter)) []byte {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text(op)
	fields(w)
	return w.buf
}

//--------------------------------------------------------------------------------------------------
// End-to-end: drive Serve over a net.Pipe and check each reply byte-for-byte
//--------------------------------------------------------------------------------------------------

func TestServeRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(server, newMemFS()) }()

	if err := writeHello(client); err != nil {
		t.Fatal(err)
	}
	if _, err := readHello(client); err != nil {
		t.Fatal(err)
	}

	var nextID uint64
	call := func(payload []byte) []byte {
		nextID++
		if err := writeFrame(client, nextID, payload); err != nil {
			t.Fatal(err)
		}
		_, resp, err := readFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// StatFs (served by the embedded ReadOnly default).
	got := call(reqUnit("StatFs"))
	if want := respStatFs(StatFs{Bsize: 4096, Frsize: 4096, Namemax: 255}); !bytes.Equal(got, want) {
		t.Errorf("StatFs: got %x want %x", got, want)
	}

	// Create /f.
	got = call(reqOp("Create", func(w *cborWriter) {
		w.mapHeader(2)
		w.text("path")
		w.bytes([]byte("/f"))
		w.text("attr")
		encodeAttr(w, FileAttr(0o644, 0))
	}))
	if want := respAttr(FileAttr(0o644, 0)); !bytes.Equal(got, want) {
		t.Errorf("Create: got %x want %x", got, want)
	}

	// Write "hello" to /f.
	got = call(reqOp("Write", func(w *cborWriter) {
		w.mapHeader(3)
		w.text("path")
		w.bytes([]byte("/f"))
		w.text("offset")
		w.uint(0)
		w.text("data")
		w.bytes([]byte("hello"))
	}))
	if want := respCount(5); !bytes.Equal(got, want) {
		t.Errorf("Write: got %x want %x", got, want)
	}

	// Read it back.
	got = call(reqOp("Read", func(w *cborWriter) {
		w.mapHeader(3)
		w.text("path")
		w.bytes([]byte("/f"))
		w.text("offset")
		w.uint(0)
		w.text("size")
		w.uint(64)
	}))
	if want := respBytes([]byte("hello")); !bytes.Equal(got, want) {
		t.Errorf("Read: got %x want %x", got, want)
	}

	// GetAttr reflects the written size.
	got = call(reqOp("GetAttr", func(w *cborWriter) {
		w.mapHeader(1)
		w.text("path")
		w.bytes([]byte("/f"))
	}))
	if want := respAttr(FileAttr(0o644, 5)); !bytes.Equal(got, want) {
		t.Errorf("GetAttr: got %x want %x", got, want)
	}

	// ReadDir / lists the new file.
	got = call(reqOp("ReadDir", func(w *cborWriter) {
		w.mapHeader(1)
		w.text("path")
		w.bytes([]byte("/"))
	}))
	if want := respDir([]DirEntry{{Name: []byte("f"), Kind: File}}); !bytes.Equal(got, want) {
		t.Errorf("ReadDir: got %x want %x", got, want)
	}

	// A missing path yields ENOENT on the wire.
	got = call(reqOp("GetAttr", func(w *cborWriter) {
		w.mapHeader(1)
		w.text("path")
		w.bytes([]byte("/nope"))
	}))
	if want := respErr(int32(ENOENT)); !bytes.Equal(got, want) {
		t.Errorf("GetAttr missing: got %x want %x", got, want)
	}

	// A read-only default (Symlink) surfaces ENOSYS.
	got = call(reqOp("Symlink", func(w *cborWriter) {
		w.mapHeader(2)
		w.text("path")
		w.bytes([]byte("/l"))
		w.text("target")
		w.bytes([]byte("f"))
	}))
	if want := respErr(int32(ENOSYS)); !bytes.Equal(got, want) {
		t.Errorf("Symlink: got %x want %x", got, want)
	}

	client.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
}

// A decode-time limit violation keeps its typed errno on the wire (matching
// the Rust server's decode_error_errno): an over-long symlink target reports
// ENAMETOOLONG, not a generic EINVAL.
func TestServeReportsDecodeLimitErrno(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(server, newMemFS()) }()

	if err := writeHello(client); err != nil {
		t.Fatal(err)
	}
	if _, err := readHello(client); err != nil {
		t.Fatal(err)
	}

	w := &cborWriter{}
	w.mapHeader(1)
	w.text("Symlink")
	w.mapHeader(2)
	w.text("path")
	w.bytes([]byte("/l"))
	w.text("target")
	w.bytes(bytes.Repeat([]byte("t"), maxSymlinkTarget+1))
	if err := writeFrame(client, 1, w.buf); err != nil {
		t.Fatal(err)
	}
	_, got, err := readFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if want := respErr(int32(ENAMETOOLONG)); !bytes.Equal(got, want) {
		t.Errorf("oversized symlink target: got %x want %x", got, want)
	}

	client.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
}

//--------------------------------------------------------------------------------------------------
// Hardening: decode-time limits, bounded allocation, range/overflow checks
//--------------------------------------------------------------------------------------------------

// A GetAttrMany batch over maxBatchPaths is rejected at decode, matching the
// Rust server's validate_request_limits.
func TestDecodeRejectsOversizedBatch(t *testing.T) {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("GetAttrMany")
	w.mapHeader(1)
	w.text("paths")
	w.arrayHeader(maxBatchPaths + 1)
	for i := 0; i < maxBatchPaths+1; i++ {
		w.bytes([]byte("/p"))
	}
	if _, err := decodeRequest(w.buf); err == nil {
		t.Fatal("expected oversized batch to be rejected")
	}
}

// A tiny frame whose array header declares a huge length must not trigger a
// multi-gigabyte allocation; it is rejected as truncated instead.
func TestReadByteArrayRejectsHugeLengthHeader(t *testing.T) {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("GetAttrMany")
	w.mapHeader(1)
	w.text("paths")
	w.arrayHeader(0xFFFFFFFF) // claims ~4 billion entries, supplies none
	if _, err := decodeRequest(w.buf); err == nil {
		t.Fatal("expected huge array-length header to be rejected")
	}
}

// An attr with an out-of-range node kind is rejected, matching node_kind_from_u8.
func TestDecodeAttrRejectsUnknownKind(t *testing.T) {
	w := &cborWriter{}
	w.mapHeader(10)
	w.text("kind")
	w.uint(99)
	for _, k := range []string{"mode", "size", "uid", "gid"} {
		w.text(k)
		w.uint(0)
	}
	w.text("nlink")
	w.null()
	w.text("rdev")
	w.uint(0)
	for _, k := range []string{"atime", "mtime", "ctime"} {
		w.text(k)
		w.null()
	}
	if _, err := decodeAttr(newCborReader(w.buf)); err == nil {
		t.Fatal("expected unknown node kind to be rejected")
	}
}

// A u32 field carrying a value above 2^32-1 is rejected rather than silently
// truncated.
func TestReadU32RejectsOverflow(t *testing.T) {
	w := &cborWriter{}
	w.mapHeader(1)
	w.text("Read")
	w.mapHeader(3)
	w.text("path")
	w.bytes([]byte("/f"))
	w.text("offset")
	w.uint(0)
	w.text("size")
	w.uint(1 << 32) // overflows u32
	if _, err := decodeRequest(w.buf); err == nil {
		t.Fatal("expected u32 overflow to be rejected")
	}
}
