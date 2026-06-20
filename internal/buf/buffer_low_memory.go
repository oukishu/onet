//go:build with_low_memory

package buf

const (
	// BufferSize is the reduced TCP/generic buffer size for low-memory targets (16 KB).
	BufferSize = 16 * 1024
	// UDPBufferSize is the reduced UDP packet buffer size for low-memory targets (8 KB).
	UDPBufferSize = 8 * 1024
)
