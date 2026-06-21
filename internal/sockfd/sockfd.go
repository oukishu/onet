package sockfd

import (
	"errors"
	"syscall"
)

func WithFD(conn syscall.Conn, operations ...func(fd uintptr) error) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var innerErr error
	err = rawConn.Control(func(fd uintptr) {
		for _, op := range operations {
			if op == nil {
				continue
			}
			if innerErr = op(fd); innerErr != nil {
				return
			}
		}
	})
	return errors.Join(innerErr, err)
}

func WithFD0[T any](conn syscall.Conn, fn func(fd uintptr) (T, error)) (T, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		var zero T
		return zero, err
	}
	var (
		val      T
		innerErr error
	)
	err = rawConn.Control(func(fd uintptr) {
		val, innerErr = fn(fd)
	})
	return val, errors.Join(innerErr, err)
}
