package uot

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestRoundTripAndShortBuffer(t *testing.T) {
	left, right := net.Pipe()
	a, err := NewConn(left, Config{MaxPacket: 128})
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewConn(right, Config{MaxPacket: 128})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	payload := []byte("udp-over-etp")
	addr := packetAddr("192.0.2.10:5353")
	writeDone := make(chan error, 1)
	go func() {
		_, err := a.WriteTo(payload, addr)
		writeDone <- err
	}()
	buffer := make([]byte, 4)
	n, gotAddr, err := b.ReadFrom(buffer)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short read error = %v", err)
	}
	if n != len(buffer) || gotAddr.String() != addr.String() || !bytes.Equal(buffer, payload[:len(buffer)]) {
		t.Fatalf("short packet mismatch: n=%d addr=%v payload=%q", n, gotAddr, buffer)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestValidationAndTerminalMalformedFrame(t *testing.T) {
	left, right := net.Pipe()
	a, err := NewConn(left, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer right.Close()
	if _, err := NewConn(right, Config{MaxPacket: 65536}); err == nil {
		t.Fatal("oversized packet limit accepted")
	}

	bad := []byte{protocolVersion, 0, 0, 1, 0, 1, 0, 0}
	go func() { _, _ = right.Write(bad) }()
	if _, _, err := a.ReadFrom(make([]byte, 1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("malformed frame error = %v", err)
	}
	if _, err := a.WriteTo([]byte("x"), packetAddr("127.0.0.1:1")); !errors.Is(err, ErrProtocol) {
		t.Fatalf("write after malformed frame = %v", err)
	}
}

func TestReadDeadline(t *testing.T) {
	left, right := net.Pipe()
	a, err := NewConn(left, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer right.Close()
	if err := a.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("read without deadline error")
	}
}
