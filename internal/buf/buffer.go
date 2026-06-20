package buf

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
)

// Buffer is a reference-counted, pool-backed byte buffer.
//
// Lifecycle rules:
//   - Buffers obtained via New/NewPacket/NewSize are pool-managed (managed=true).
//   - Call Release() exactly once when the buffer is no longer needed.
//   - If a buffer is shared across goroutines, use IncRef/DecRef to track
//     additional owners; Release() will not return to pool while refs > 0.
//   - Buffers created via As/With are NOT pool-managed; Release() is a no-op.
type Buffer struct {
	data     []byte
	start    int
	end      int
	capacity int
	refs     atomic.Int32
	managed  bool
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

// New allocates a pool-managed Buffer of BufferSize capacity.
func New() *Buffer {
	return &Buffer{
		data:     Get(BufferSize),
		capacity: BufferSize,
		managed:  true,
	}
}

// NewPacket allocates a pool-managed Buffer of UDPBufferSize capacity.
func NewPacket() *Buffer {
	return &Buffer{
		data:     Get(UDPBufferSize),
		capacity: UDPBufferSize,
		managed:  true,
	}
}

// NewSize allocates a pool-managed Buffer of the given capacity.
// If size is 0 an empty unmanaged Buffer is returned.
// If size > 65535 the backing slice is heap-allocated (not pooled).
func NewSize(size int) *Buffer {
	if size == 0 {
		return &Buffer{}
	} else if size > 65535 {
		return &Buffer{
			data:     make([]byte, size),
			capacity: size,
		}
	}
	return &Buffer{
		data:     Get(size),
		capacity: size,
		managed:  true,
	}
}

// As wraps an existing []byte as a full-content Buffer (not pool-managed).
// The buffer's content view covers all bytes in data.
func As(data []byte) *Buffer {
	return &Buffer{
		data:     data,
		end:      len(data),
		capacity: len(data),
	}
}

// With wraps an existing []byte as an empty Buffer (not pool-managed).
// The buffer is empty but can be written into up to cap(data).
func With(data []byte) *Buffer {
	return &Buffer{
		data:     data,
		capacity: len(data),
	}
}

// ---------------------------------------------------------------------------
// Read-only accessors
// ---------------------------------------------------------------------------

// Bytes returns the current readable slice [start, end).
func (b *Buffer) Bytes() []byte {
	return b.data[b.start:b.end]
}

// Len returns the number of readable bytes.
func (b *Buffer) Len() int {
	return b.end - b.start
}

// Cap returns the writable capacity (may be less than len(data) when Reserve
// has been called).
func (b *Buffer) Cap() int {
	return b.capacity
}

// RawCap returns the total length of the underlying data slice.
func (b *Buffer) RawCap() int {
	return len(b.data)
}

// Start returns the current start offset within the underlying slice.
func (b *Buffer) Start() int {
	return b.start
}

// FreeLen returns the number of bytes that can still be appended.
func (b *Buffer) FreeLen() int {
	return b.capacity - b.end
}

// FreeBytes returns the writable region [end, capacity).
func (b *Buffer) FreeBytes() []byte {
	return b.data[b.end:b.capacity]
}

// IsEmpty reports whether the buffer contains no readable bytes.
func (b *Buffer) IsEmpty() bool {
	return b.end == b.start
}

// IsFull reports whether the writable region is exhausted.
func (b *Buffer) IsFull() bool {
	return b.end == b.capacity
}

// ---------------------------------------------------------------------------
// Sub-slice helpers (used by stack_system.go / ping/)
// ---------------------------------------------------------------------------

// From returns the readable slice starting at offset n from start.
func (b *Buffer) From(n int) []byte {
	return b.data[b.start+n : b.end]
}

// To returns the first n readable bytes.
func (b *Buffer) To(n int) []byte {
	return b.data[b.start : b.start+n]
}

// Range returns the readable slice [start+s, start+e).
func (b *Buffer) Range(s, e int) []byte {
	return b.data[b.start+s : b.start+e]
}

// Index returns a zero-length slice anchored at start+s, useful for obtaining
// a pointer into the buffer without copying.
func (b *Buffer) Index(s int) []byte {
	return b.data[b.start+s : b.start+s]
}

// ---------------------------------------------------------------------------
// Mutation — pointer moves
// ---------------------------------------------------------------------------

// Advance moves the start pointer forward by n bytes, shrinking the readable
// region. If n is negative the start pointer moves backward (prepend region).
// Panics if the resulting start would underflow 0 or overflow end.
func (b *Buffer) Advance(n int) {
	b.start += n
	if b.end < b.start {
		b.end = b.start
	}
}

// Truncate sets the end pointer so that exactly n bytes are readable from
// the current start.
func (b *Buffer) Truncate(to int) {
	b.end = b.start + to
}

// Resize sets start and end explicitly (end is relative to start).
func (b *Buffer) Resize(start, end int) {
	b.start = start
	b.end = b.start + end
}

// Reset resets the buffer to its initial empty state, restoring full capacity.
func (b *Buffer) Reset() {
	b.start = 0
	b.end = 0
	b.capacity = len(b.data)
}

// ---------------------------------------------------------------------------
// Mutation — append / prepend
// ---------------------------------------------------------------------------

// Extend grows the writable end by n bytes and returns the newly allocated
// slice. Panics on overflow.
func (b *Buffer) Extend(n int) []byte {
	end := b.end + n
	if end > b.capacity {
		panic(fmt.Sprintf("buf.Buffer: Extend overflow: capacity=%d end=%d need=%d",
			b.capacity, b.end, n))
	}
	ext := b.data[b.end:end]
	b.end = end
	return ext
}

// ExtendHeader grows the header region (before start) by n bytes and returns
// the slice covering the new header area. Panics if start < n.
func (b *Buffer) ExtendHeader(n int) []byte {
	if b.start < n {
		panic(fmt.Sprintf("buf.Buffer: ExtendHeader overflow: capacity=%d start=%d need=%d",
			b.capacity, b.start, n))
	}
	b.start -= n
	return b.data[b.start : b.start+n]
}

// Reserve reduces the effective capacity by n bytes from the tail. This
// reserves space for a trailer that will be filled later via OverCap.
// Panics if n > capacity.
func (b *Buffer) Reserve(n int) {
	if n > b.capacity {
		panic(fmt.Sprintf("buf.Buffer: Reserve overflow: capacity=%d need=%d",
			b.capacity, n))
	}
	b.capacity -= n
}

// OverCap expands the effective capacity by n bytes previously reserved with
// Reserve. Panics if the expansion would exceed the underlying slice length.
func (b *Buffer) OverCap(n int) {
	if b.capacity+n > len(b.data) {
		panic(fmt.Sprintf("buf.Buffer: OverCap overflow: rawCap=%d need=%d",
			len(b.data), b.capacity+n))
	}
	b.capacity += n
}

// ---------------------------------------------------------------------------
// Write methods (append to tail)
// ---------------------------------------------------------------------------

// Write appends p to the buffer, returning the number of bytes written.
// Returns io.ErrShortBuffer if the buffer is full.
func (b *Buffer) Write(data []byte) (n int, err error) {
	if len(data) == 0 {
		return
	}
	if b.IsFull() {
		return 0, io.ErrShortBuffer
	}
	n = copy(b.data[b.end:b.capacity], data)
	b.end += n
	return
}

// WriteByte appends a single byte. Returns io.ErrShortBuffer if full.
func (b *Buffer) WriteByte(d byte) error {
	if b.IsFull() {
		return io.ErrShortBuffer
	}
	b.data[b.end] = d
	b.end++
	return nil
}

// WriteZeroN appends n zero bytes. Returns io.ErrShortBuffer if insufficient
// space.
func (b *Buffer) WriteZeroN(n int) error {
	if b.end+n > b.capacity {
		return io.ErrShortBuffer
	}
	clear(b.Extend(n))
	return nil
}

// ---------------------------------------------------------------------------
// Byte accessors
// ---------------------------------------------------------------------------

// Byte returns the byte at logical index i (relative to start).
func (b *Buffer) Byte(index int) byte {
	return b.data[b.start+index]
}

// SetByte sets the byte at logical index i.
func (b *Buffer) SetByte(index int, value byte) {
	b.data[b.start+index] = value
}

// ---------------------------------------------------------------------------
// Read methods (consume from head)
// ---------------------------------------------------------------------------

// ReadOnceFrom reads once from r into the free region, advancing end.
// Returns io.ErrShortBuffer if there is no free space.
func (b *Buffer) ReadOnceFrom(r io.Reader) (int, error) {
	if b.IsFull() {
		return 0, io.ErrShortBuffer
	}
	n, err := r.Read(b.FreeBytes())
	b.end += n
	return n, err
}

// ReadFrom reads from r until EOF or the buffer is full, advancing end.
// io.EOF is consumed and not returned as an error.
func (b *Buffer) ReadFrom(reader io.Reader) (n int64, err error) {
	for {
		if b.IsFull() {
			return 0, io.ErrShortBuffer
		}
		var rn int
		rn, err = reader.Read(b.FreeBytes())
		b.end += rn
		n += int64(rn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return
		}
	}
}

// ReadPacketFrom reads a single datagram from r into the free region.
func (b *Buffer) ReadPacketFrom(r net.PacketConn) (int64, net.Addr, error) {
	if b.IsFull() {
		return 0, nil, io.ErrShortBuffer
	}
	n, addr, err := r.ReadFrom(b.FreeBytes())
	b.end += n
	return int64(n), addr, err
}

// ReadFullFrom reads exactly size bytes from r into the free region.
func (b *Buffer) ReadFullFrom(r io.Reader, size int) (n int, err error) {
	if b.end+size > b.capacity {
		return 0, io.ErrShortBuffer
	}
	n, err = io.ReadFull(r, b.data[b.end:b.end+size])
	b.end += n
	return
}

// WriteTo writes all readable bytes to w.
func (b *Buffer) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(b.Bytes())
	return int64(n), err
}

// ---------------------------------------------------------------------------
// Reference counting & lifecycle
// ---------------------------------------------------------------------------

// IncRef increments the reference count. Call when sharing a Buffer across
// goroutines; Release will not return to pool until all refs reach zero.
func (b *Buffer) IncRef() {
	b.refs.Add(1)
}

// DecRef decrements the reference count.
func (b *Buffer) DecRef() {
	b.refs.Add(-1)
}

// Release returns the buffer to the pool if it is pool-managed and has no
// outstanding references. Safe to call on nil.
func (b *Buffer) Release() {
	if b == nil || !b.managed {
		return
	}
	if b.refs.Load() > 0 {
		return
	}
	if err := Put(b.data); err != nil {
		panic(err)
	}
	*b = Buffer{}
}

// ---------------------------------------------------------------------------
// Ownership transfer
// ---------------------------------------------------------------------------

// ToOwned returns a new pool-managed Buffer that is an independent copy of
// the current buffer's readable content, preserving start/end/capacity layout.
// Used when a caller needs to take ownership of data sourced from a read-only
// or externally-owned slice (e.g. buf.As(slice).ToOwned()).
func (b *Buffer) ToOwned() *Buffer {
	n := NewSize(len(b.data))
	copy(n.data[b.start:b.end], b.data[b.start:b.end])
	n.start = b.start
	n.end = b.end
	n.capacity = b.capacity
	return n
}
