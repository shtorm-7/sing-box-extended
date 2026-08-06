package livekit

import "fmt"

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

type pbWriter struct{ buf []byte }

func (w *pbWriter) varint(v uint64) {
	for v >= 0x80 {
		w.buf = append(w.buf, byte(v)|0x80)
		v >>= 7
	}
	w.buf = append(w.buf, byte(v))
}

func (w *pbWriter) tag(field, wire uint64) { w.varint(field<<3 | wire) }

func (w *pbWriter) string(field uint64, s string) {
	w.tag(field, wireBytes)
	w.varint(uint64(len(s)))
	w.buf = append(w.buf, s...)
}

func (w *pbWriter) bytes(field uint64, b []byte) {
	w.tag(field, wireBytes)
	w.varint(uint64(len(b)))
	w.buf = append(w.buf, b...)
}

func (w *pbWriter) message(field uint64, b []byte) { w.bytes(field, b) }

func (w *pbWriter) int32(field uint64, v int32) {
	w.tag(field, wireVarint)
	w.varint(uint64(uint32(v)))
}

func (w *pbWriter) int64(field uint64, v int64) {
	w.tag(field, wireVarint)
	w.varint(uint64(v))
}

func (w *pbWriter) uint32(field uint64, v uint32) {
	w.tag(field, wireVarint)
	w.varint(uint64(v))
}

func (w *pbWriter) bool(field uint64, v bool) {
	w.tag(field, wireVarint)
	if v {
		w.varint(1)
	} else {
		w.varint(0)
	}
}

type pbReader struct {
	buf []byte
	pos int
}

func (r *pbReader) eof() bool { return r.pos >= len(r.buf) }

func (r *pbReader) varint() (uint64, error) {
	var v uint64
	var shift uint
	for {
		if r.pos >= len(r.buf) {
			return 0, fmt.Errorf("varint: unexpected eof")
		}
		b := r.buf[r.pos]
		r.pos++
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, nil
		}
		shift += 7
		if shift >= 64 {
			return 0, fmt.Errorf("varint: overflow")
		}
	}
}

func (r *pbReader) tag() (field, wire uint64, err error) {
	t, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	return t >> 3, t & 7, nil
}

func (r *pbReader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if r.pos+int(n) > len(r.buf) {
		return nil, fmt.Errorf("bytes: short read")
	}
	out := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, nil
}

func (r *pbReader) skipWire(wire uint64) error {
	switch wire {
	case wireVarint:
		_, err := r.varint()
		return err
	case wireFixed64:
		if r.pos+8 > len(r.buf) {
			return fmt.Errorf("skip: short fixed64")
		}
		r.pos += 8
		return nil
	case wireBytes:
		_, err := r.bytes()
		return err
	case wireFixed32:
		if r.pos+4 > len(r.buf) {
			return fmt.Errorf("skip: short fixed32")
		}
		r.pos += 4
		return nil
	}
	return fmt.Errorf("unknown wire type %d", wire)
}
