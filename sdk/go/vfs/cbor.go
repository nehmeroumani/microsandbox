package vfs

// Minimal, dependency-free CBOR codec covering exactly the subset the VFS wire
// protocol uses: unsigned/negative integers, byte and text strings, definite
// arrays and maps, booleans, and null. Integers are written in the shortest
// form, matching the Rust `ciborium` encoder byte-for-byte (see
// wire_vectors_test.go).

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// CBOR major types (high 3 bits of the initial byte).
const (
	majUint  = 0
	majNeg   = 1
	majBytes = 2
	majText  = 3
	majArray = 4
	majMap   = 5
	majOther = 7 // simple values: false/true/null
)

//--------------------------------------------------------------------------------------------------
// Encoder
//--------------------------------------------------------------------------------------------------

type cborWriter struct {
	buf []byte
}

// head writes the initial byte and minimal-length argument for `major`.
func (w *cborWriter) head(major byte, n uint64) {
	switch {
	case n < 24:
		w.buf = append(w.buf, major<<5|byte(n))
	case n < 1<<8:
		w.buf = append(w.buf, major<<5|24, byte(n))
	case n < 1<<16:
		w.buf = append(w.buf, major<<5|25, byte(n>>8), byte(n))
	case n < 1<<32:
		w.buf = append(w.buf, major<<5|26)
		w.buf = binary.BigEndian.AppendUint32(w.buf, uint32(n))
	default:
		w.buf = append(w.buf, major<<5|27)
		w.buf = binary.BigEndian.AppendUint64(w.buf, n)
	}
}

func (w *cborWriter) uint(n uint64) { w.head(majUint, n) }

func (w *cborWriter) int(i int64) {
	if i >= 0 {
		w.head(majUint, uint64(i))
	} else {
		w.head(majNeg, uint64(-1-i))
	}
}

func (w *cborWriter) bytes(b []byte) {
	w.head(majBytes, uint64(len(b)))
	w.buf = append(w.buf, b...)
}

func (w *cborWriter) text(s string) {
	w.head(majText, uint64(len(s)))
	w.buf = append(w.buf, s...)
}

func (w *cborWriter) arrayHeader(n int) { w.head(majArray, uint64(n)) }
func (w *cborWriter) mapHeader(n int)   { w.head(majMap, uint64(n)) }
func (w *cborWriter) null()             { w.buf = append(w.buf, majOther<<5|22) }

//--------------------------------------------------------------------------------------------------
// Decoder
//--------------------------------------------------------------------------------------------------

type cborReader struct {
	data []byte
	pos  int
}

func newCborReader(data []byte) *cborReader { return &cborReader{data: data} }

// remaining reports how many unread bytes are left in the buffer.
func (r *cborReader) remaining() int { return len(r.data) - r.pos }

func (r *cborReader) takeByte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	b := r.data[r.pos]
	r.pos++
	return b, nil
}

// head reads the initial byte and its argument, returning the major type.
func (r *cborReader) head() (major byte, arg uint64, err error) {
	b, err := r.takeByte()
	if err != nil {
		return 0, 0, err
	}
	major = b >> 5
	ai := b & 0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		x, err := r.takeByte()
		return major, uint64(x), err
	case ai == 25:
		if r.pos+2 > len(r.data) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		arg = uint64(binary.BigEndian.Uint16(r.data[r.pos:]))
		r.pos += 2
		return major, arg, nil
	case ai == 26:
		if r.pos+4 > len(r.data) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		arg = uint64(binary.BigEndian.Uint32(r.data[r.pos:]))
		r.pos += 4
		return major, arg, nil
	case ai == 27:
		if r.pos+8 > len(r.data) {
			return 0, 0, io.ErrUnexpectedEOF
		}
		arg = binary.BigEndian.Uint64(r.data[r.pos:])
		r.pos += 8
		return major, arg, nil
	default:
		return 0, 0, fmt.Errorf("vfs cbor: unsupported additional info %d", ai)
	}
}

func (r *cborReader) expect(major byte) (uint64, error) {
	m, arg, err := r.head()
	if err != nil {
		return 0, err
	}
	if m != major {
		return 0, fmt.Errorf("vfs cbor: expected major %d, got %d", major, m)
	}
	return arg, nil
}

func (r *cborReader) readUint() (uint64, error) { return r.expect(majUint) }

func (r *cborReader) readU32() (uint32, error) {
	n, err := r.readUint()
	if err != nil {
		return 0, err
	}
	if n > math.MaxUint32 {
		return 0, fmt.Errorf("vfs cbor: integer %d overflows u32", n)
	}
	return uint32(n), nil
}

func (r *cborReader) readInt() (int64, error) {
	m, arg, err := r.head()
	if err != nil {
		return 0, err
	}
	switch m {
	case majUint:
		return int64(arg), nil
	case majNeg:
		return -1 - int64(arg), nil
	default:
		return 0, fmt.Errorf("vfs cbor: expected integer, got major %d", m)
	}
}

func (r *cborReader) readBool() (bool, error) {
	b, err := r.takeByte()
	if err != nil {
		return false, err
	}
	switch b {
	case majOther<<5 | 20:
		return false, nil
	case majOther<<5 | 21:
		return true, nil
	default:
		return false, fmt.Errorf("vfs cbor: expected bool, got 0x%02x", b)
	}
}

func (r *cborReader) readBytes() ([]byte, error) {
	n, err := r.expect(majBytes)
	if err != nil {
		return nil, err
	}
	end := r.pos + int(n)
	if n > uint64(len(r.data)) || end > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]byte, n)
	copy(out, r.data[r.pos:end])
	r.pos = end
	return out, nil
}

func (r *cborReader) readText() (string, error) {
	n, err := r.expect(majText)
	if err != nil {
		return "", err
	}
	end := r.pos + int(n)
	if n > uint64(len(r.data)) || end > len(r.data) {
		return "", io.ErrUnexpectedEOF
	}
	s := string(r.data[r.pos:end])
	r.pos = end
	return s, nil
}

func (r *cborReader) readArrayHeader() (int, error) {
	n, err := r.expect(majArray)
	return int(n), err
}

func (r *cborReader) readMapHeader() (int, error) {
	n, err := r.expect(majMap)
	return int(n), err
}

// tryNull consumes a null if the next item is one, reporting whether it did.
func (r *cborReader) tryNull() bool {
	if r.pos < len(r.data) && r.data[r.pos] == majOther<<5|22 {
		r.pos++
		return true
	}
	return false
}
