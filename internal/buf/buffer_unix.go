//go:build !windows

package buf

import "golang.org/x/sys/unix"

// Iovec returns a unix.Iovec pointing at the start of the buffer's readable
// region with the given length. Used by tun_darwin.go for recvmsg/sendmsg
// zero-copy batch I/O via writev/readv system calls.
func (b *Buffer) Iovec(length int) unix.Iovec {
	var iov unix.Iovec
	iov.Base = &b.data[b.start]
	iov.SetLen(length)
	return iov
}
