package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"Enigma/internal/tunnel"
)

func TestHTTPConnectSelector(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	selectionCh := make(chan TargetSelection, 1)
	errCh := make(chan error, 1)
	go func() {
		selection, err := HTTPConnectSelector(server)
		selectionCh <- selection
		errCh <- err
	}()
	request := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	selection := <-selectionCh
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if selection.Address != "example.com:443" {
		t.Fatalf("target = %q", selection.Address)
	}
	responseErr := make(chan error, 1)
	go func() { responseErr <- selection.Respond(nil) }()
	response := readHTTPResponse(t, client)
	if err := <-responseErr; err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(response, []byte("HTTP/1.1 200 Connection Established\r\n")) {
		t.Fatalf("response = %q", response)
	}
}

func TestHTTPConnectRejectsNonConnect(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errCh := make(chan error, 1)
	go func() {
		_, err := HTTPConnectSelector(server)
		errCh <- err
	}()
	requestDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("GET http://example.com/ HTTP/1.1\r\n\r\n"))
		requestDone <- err
	}()
	response := readHTTPResponse(t, client)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(response, []byte("HTTP/1.1 405 Method Not Allowed\r\n")) {
		t.Fatalf("response = %q", response)
	}
	if err := <-errCh; !errors.Is(err, errHTTPConnectRequest) {
		t.Fatalf("selector error = %v", err)
	}
}

func TestHTTPConnectTargetForwardingEndToEnd(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	echoDone := make(chan error, 1)
	go func() {
		conn, err := echoListener.Accept()
		if err != nil {
			echoDone <- err
			return
		}
		defer conn.Close()
		_, err = io.Copy(conn, conn)
		echoDone <- err
	}()
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := tunnel.NewReplayGuard(64, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	codec := testCodecConfig()
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	targetAddress := echoListener.Addr().String()
	go func() {
		serverDone <- ServeServer(ctx, serverListener, ServerConfig{
			Tunnel:      tunnel.Config{Codec: codec, ReplayGuard: guard, MaxClockSkew: time.Minute},
			AllowTarget: func(address string) bool { return address == targetAddress },
		})
	}()
	go func() {
		clientDone <- ServeClient(ctx, clientListener, ClientConfig{
			Tunnel:                tunnel.Config{Codec: codec, MaxClockSkew: time.Minute},
			ServerAddress:         serverListener.Addr().String(),
			TargetSelector:        HTTPConnectSelector,
			LocalHandshakeTimeout: time.Second,
		})
	}()

	local, err := net.Dial("tcp", clientListener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := local.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := "CONNECT " + targetAddress + " HTTP/1.1\r\nHost: " + targetAddress + "\r\n\r\n"
	if _, err := local.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	response := readHTTPResponse(t, local)
	if !bytes.HasPrefix(response, []byte("HTTP/1.1 200 Connection Established\r\n")) {
		t.Fatalf("connect response = %q", response)
	}
	payload := bytes.Repeat([]byte("http connect payload"), 128)
	if _, err := local.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(local, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("HTTP CONNECT payload mismatch")
	}
	_ = local.Close()
	cancel()
	waitServeResult(t, "server", serverDone)
	waitServeResult(t, "client", clientDone)
	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatalf("echo server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("echo server did not finish")
	}
}

func readHTTPResponse(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	response := make([]byte, 0, 256)
	var last [4]byte
	for len(response) < 16*1024 {
		var one [1]byte
		if _, err := reader.Read(one[:]); err != nil {
			t.Fatal(err)
		}
		response = append(response, one[0])
		last[0], last[1], last[2], last[3] = last[1], last[2], last[3], one[0]
		if string(last[:]) == "\r\n\r\n" {
			return response
		}
	}
	t.Fatal("HTTP response headers too large")
	return nil
}
