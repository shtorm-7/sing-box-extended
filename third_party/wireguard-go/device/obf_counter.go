package device

import (
	"encoding/binary"
	"sync/atomic"
)

func newCounterObf(_ string) (obf, error) {
	return &counterObf{}, nil
}

type counterObf struct {
	counter uint32
}

func (o *counterObf) Obfuscate(dst, src []byte) {
	val := atomic.AddUint32(&o.counter, 1) - 1
	binary.BigEndian.PutUint32(dst, val)
}

func (o *counterObf) Deobfuscate(dst, src []byte) bool {
	return true
}

func (o *counterObf) ObfuscatedLen(n int) int {
	return 4
}

func (o *counterObf) DeobfuscatedLen(n int) int {
	return 0
}
