package sockfd

import (
	"syscall"
)

func WithFD(conn syscall.Conn, fn func(fd uintptr) error) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	err = raw.Control(func(fd uintptr) {
		inner = fn(fd)
	})
	if inner != nil {
		return inner
	}
	return err
}

func WithFD0[T any](conn syscall.Conn, fn func(fd uintptr) (T, error)) (T, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		var zero T
		return zero, err
	}
	var (
		val   T
		inner error
	)
	err = raw.Control(func(fd uintptr) {
		val, inner = fn(fd)
	})
	if inner != nil {
		return val, inner
	}
	return val, err
}
