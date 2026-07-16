package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"Enigma/internal/tunnel"
)

func TestSOCKS5SelectorDomainRequest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	result := make(chan TargetSelection, 1)
	errCh := make(chan error, 1)
	go func() {
		selection, err := SOCKS5Selector(server)
		result <- selection
		errCh <- err
	}()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(method, []byte{5, 0}) {
		t.Fatalf("method response = %x", method)
	}
	request := []byte{5, 1, 0, 3, 11}
	request = append(request, []byte("example.com")...)
	request = append(request, 0x01, 0xbb)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	selection := <-result
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if selection.Address != "example.com:443" {
		t.Fatalf("target = %q", selection.Address)
	}
	responseErr := make(chan error, 1)
	go func() { responseErr <- selection.Respond(nil) }()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if err := <-responseErr; err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("success reply = %x", reply)
	}
}

func TestSOCKS5SelectorFailureReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	result := make(chan TargetSelection, 1)
	errCh := make(chan error, 1)
	go func() {
		selection, err := SOCKS5Selector(server)
		result <- selection
		errCh <- err
	}()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil {
		t.Fatal(err)
	}
	if method[1] != 0 {
		t.Fatalf("method reply = %x", method)
	}
	if _, err := client.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	selection := <-result
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	responseErr := make(chan error, 1)
	go func() { responseErr <- selection.Respond(tunnel.ErrTargetRejected) }()
	reply := readSOCKSReply(t, client)
	if err := <-responseErr; err != nil {
		t.Fatal(err)
	}
	if reply[1] != 5 {
		t.Fatalf("rejection reply = %x", reply)
	}
}

func TestSOCKS5NoAuthRequired(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		_, err := SOCKS5Selector(server)
		done <- err
	}()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, []byte{5, 0xff}) {
		t.Fatalf("no-auth reply = %x", reply)
	}
	if !errors.Is(<-done, errSOCKS5NoAcceptableMethod) {
		t.Fatal("missing no-auth error")
	}
}

func TestSOCKS5TargetForwardingEndToEnd(t *testing.T) {
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
			TargetSelector:        SOCKS5Selector,
			LocalHandshakeTimeout: time.Second,
		})
	}()

	local, err := net.Dial("tcp", clientListener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer local.Close()
	if err := local.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := local.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(local, method); err != nil {
		t.Fatal(err)
	}
	if method[1] != 0 {
		t.Fatalf("method reply = %x", method)
	}
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatal("echo target is not IPv4")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte{5, 1, 0, 1}
	request = append(request, ip...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	request = append(request, portBytes[:]...)
	if _, err := local.Write(request); err != nil {
		t.Fatal(err)
	}
	if reply := readSOCKSReply(t, local); reply[1] != 0 {
		t.Fatalf("connect reply = %x", reply)
	}
	payload := bytes.Repeat([]byte("socks5 payload"), 128)
	if _, err := local.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(local, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("SOCKS5 payload mismatch")
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

func readSOCKSReply(t *testing.T, reader io.Reader) []byte {
	t.Helper()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatal(err)
	}
	return reply
}
