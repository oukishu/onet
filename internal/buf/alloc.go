package buf

// Inspired by https://github.com/xtaci/smux/blob/master/alloc.go

import (
	"errors"
	"math/bits"
	"sync"
)

var DefaultAllocator = newDefaultAllocator()

type Allocator interface {
	Get(size int) []byte
	Put(buf []byte) error
}

// defaultAllocator for incoming frames, optimized to prevent overwriting after zeroing.
// Pools cover 64B → 64KB in powers of two (11 buckets).
type defaultAllocator struct {
	buffers [11]sync.Pool
}

func newDefaultAllocator() Allocator {
	return &defaultAllocator{
		buffers: [...]sync.Pool{
			{New: func() any { return new([1 << 6]byte) }},
			{New: func() any { return new([1 << 7]byte) }},
			{New: func() any { return new([1 << 8]byte) }},
			{New: func() any { return new([1 << 9]byte) }},
			{New: func() any { return new([1 << 10]byte) }},
			{New: func() any { return new([1 << 11]byte) }},
			{New: func() any { return new([1 << 12]byte) }},
			{New: func() any { return new([1 << 13]byte) }},
			{New: func() any { return new([1 << 14]byte) }},
			{New: func() any { return new([1 << 15]byte) }},
			{New: func() any { return new([1 << 16]byte) }},
		},
	}
}

// Get returns a []byte from the pool with the most appropriate capacity.
// size must be in [1, 65536]; returns nil otherwise.
func (alloc *defaultAllocator) Get(size int) []byte {
	if size <= 0 || size > 65536 {
		return nil
	}

	var index uint16
	if size > 64 {
		index = msb(size)
		if size != 1<<index {
			index++
		}
		index -= 6
	}

	buffer := alloc.buffers[index].Get()
	switch index {
	case 0:
		return buffer.(*[1 << 6]byte)[:size]
	case 1:
		return buffer.(*[1 << 7]byte)[:size]
	case 2:
		return buffer.(*[1 << 8]byte)[:size]
	case 3:
		return buffer.(*[1 << 9]byte)[:size]
	case 4:
		return buffer.(*[1 << 10]byte)[:size]
	case 5:
		return buffer.(*[1 << 11]byte)[:size]
	case 6:
		return buffer.(*[1 << 12]byte)[:size]
	case 7:
		return buffer.(*[1 << 13]byte)[:size]
	case 8:
		return buffer.(*[1 << 14]byte)[:size]
	case 9:
		return buffer.(*[1 << 15]byte)[:size]
	case 10:
		return buffer.(*[1 << 16]byte)[:size]
	default:
		panic("invalid pool index")
	}
}

// Put returns a []byte to the pool. The cap must be exactly 2^n (64 ≤ cap ≤ 65536).
func (alloc *defaultAllocator) Put(buf []byte) error {
	bits := msb(cap(buf))
	if cap(buf) < 64 || cap(buf) > 65536 || cap(buf) != 1<<bits {
		return errors.New("allocator Put() incorrect buffer size")
	}
	bits -= 6
	buf = buf[:cap(buf)]

	//nolint
	//lint:ignore SA6002 ignore temporarily
	switch bits {
	case 0:
		alloc.buffers[bits].Put((*[1 << 6]byte)(buf))
	case 1:
		alloc.buffers[bits].Put((*[1 << 7]byte)(buf))
	case 2:
		alloc.buffers[bits].Put((*[1 << 8]byte)(buf))
	case 3:
		alloc.buffers[bits].Put((*[1 << 9]byte)(buf))
	case 4:
		alloc.buffers[bits].Put((*[1 << 10]byte)(buf))
	case 5:
		alloc.buffers[bits].Put((*[1 << 11]byte)(buf))
	case 6:
		alloc.buffers[bits].Put((*[1 << 12]byte)(buf))
	case 7:
		alloc.buffers[bits].Put((*[1 << 13]byte)(buf))
	case 8:
		alloc.buffers[bits].Put((*[1 << 14]byte)(buf))
	case 9:
		alloc.buffers[bits].Put((*[1 << 15]byte)(buf))
	case 10:
		alloc.buffers[bits].Put((*[1 << 16]byte)(buf))
	default:
		panic("invalid pool index")
	}
	return nil
}

// msb returns the position of the most significant bit.
func msb(size int) uint16 {
	return uint16(bits.Len32(uint32(size)) - 1)
}
