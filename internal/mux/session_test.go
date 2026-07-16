package mux

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestSessionOpenAcceptAndRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	client, err := NewSession(left, Config{MaxFramePayload: 7, StreamBuffer: 4}, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSession(right, Config{MaxFramePayload: 7, StreamBuffer: 4}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	clientStream, err := client.Open()
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("mux-data-"), 100)
	writeDone := make(chan error, 1)
	go func() {
		_, err := clientStream.Write(payload)
		writeDone <- err
	}()
	got, err := io.ReadAll(io.LimitReader(serverStream, int64(len(payload))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(got))
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if err := clientStream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := serverStream.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server read error = %v, want EOF", err)
	}
}

func TestSessionRejectsWrongInitiatorParity(t *testing.T) {
	left, right := net.Pipe()
	client, err := NewSession(left, Config{}, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSession(right, Config{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	header := []byte{protocolVersion, frameOpen, 0, 0, 0, 1, 0, 0}
	go func() { _, _ = right.Write(header) }()
	select {
	case <-client.done:
		if !errors.Is(client.Err(), ErrProtocol) {
			t.Fatalf("client error = %v", client.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("client did not reject wrong parity")
	}
}

func TestSessionValidation(t *testing.T) {
	if _, err := NewSession(nil, Config{}, true); err == nil {
		t.Fatal("nil connection accepted")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := NewSession(left, Config{MaxFramePayload: 0}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSession(right, Config{MaxFramePayload: 65536}, false); err == nil {
		t.Fatal("oversized frame limit accepted")
	}
}

func TestStreamDeadline(t *testing.T) {
	left, right := net.Pipe()
	client, err := NewSession(left, Config{}, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSession(right, Config{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	clientStream, err := client.Open()
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := serverStream.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := serverStream.Read(make([]byte, 1)); err == nil || !errors.As(err, new(net.Error)) {
		t.Fatalf("deadline read error = %v", err)
	}
	_ = clientStream.Close()
	_ = serverStream.Close()
}
