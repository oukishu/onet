//go:build !with_low_memory

package buf

const (
	// BufferSize is the default TCP/generic buffer size (32 KB).
	BufferSize = 32 * 1024
	// UDPBufferSize is the default UDP packet buffer size (16 KB).
	UDPBufferSize = 16 * 1024
)
