package app

import (
	"errors"
	"io"
	"net"
)

func relay(left, right net.Conn) error {
	type copyResult struct {
		err error
	}
	results := make(chan copyResult, 2)
	copyDirection := func(destination, source net.Conn) {
		_, err := io.Copy(destination, source)
		closeWrite(destination)
		closeRead(source)
		results <- copyResult{err: err}
	}
	go copyDirection(left, right)
	go copyDirection(right, left)
	first := <-results
	second := <-results
	if first.err != nil && !errors.Is(first.err, net.ErrClosed) {
		return first.err
	}
	if second.err != nil && !errors.Is(second.err, net.ErrClosed) {
		return second.err
	}
	return nil
}

func closeWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = conn.Close()
}

func closeRead(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseRead() error }); ok {
		_ = closer.CloseRead()
	}
}
