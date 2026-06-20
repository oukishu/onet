package buf

import "golang.org/x/sys/windows"

// Iovec returns a windows.WSABuf pointing at the start of the buffer's
// readable region with the given length. Used by Windows TUN batch I/O
// via WSASend/WSARecv overlapped calls.
func (b *Buffer) Iovec(length int) windows.WSABuf {
	return windows.WSABuf{
		Buf: &b.data[b.start],
		Len: uint32(length),
	}
}
