package app

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"Enigma/internal/transport"
	"Enigma/internal/tunnel"
	"Enigma/pkg/enigma"
)

func TestFixedTargetForwardingEndToEnd(t *testing.T) {
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
	guard, err := tunnel.NewReplayGuard(128, 2*time.Minute)
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
			Tunnel: tunnel.Config{
				Codec:        codec,
				MaxClockSkew: time.Minute,
				ReplayGuard:  guard,
			},
			AllowTarget: func(address string) bool { return address == targetAddress },
		})
	}()
	go func() {
		clientDone <- ServeClient(ctx, clientListener, ClientConfig{
			Tunnel: tunnel.Config{
				Codec:        codec,
				MaxClockSkew: time.Minute,
			},
			ServerAddress: serverListener.Addr().String(),
			TargetAddress: targetAddress,
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
	payload := bytes.Repeat([]byte("ETPH/1 forwarding "), 1024)
	if _, err := local.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(local, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("forwarded payload mismatch")
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

func TestMuxForwardingMultipleConnections(t *testing.T) {
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	echoDone := make(chan error, 2)
	for i := 0; i < 2; i++ {
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
	}

	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := tunnel.NewReplayGuard(128, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	codec := testCodecConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	targetAddress := echoListener.Addr().String()
	go func() {
		serverDone <- ServeServer(ctx, serverListener, ServerConfig{
			Tunnel: tunnel.Config{Codec: codec, ReplayGuard: guard},
			Mux:    true,
			WrapConn: func(conn net.Conn) (net.Conn, error) {
				return transport.ServerHTTP(conn, transport.HTTPConfig{Host: "mux.example", Path: "/etph"})
			},
			AllowTarget: func(address string) bool {
				return address == targetAddress
			},
		})
	}()
	go func() {
		clientDone <- ServeClient(ctx, clientListener, ClientConfig{
			Tunnel:        tunnel.Config{Codec: codec},
			Mux:           true,
			ServerAddress: serverListener.Addr().String(),
			TargetAddress: targetAddress,
			WrapConn: func(conn net.Conn) (net.Conn, error) {
				return transport.ClientHTTP(conn, transport.HTTPConfig{Host: "mux.example", Path: "/etph"})
			},
		})
	}()

	for i := 0; i < 2; i++ {
		local, err := net.Dial("tcp", clientListener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := local.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			_ = local.Close()
			t.Fatal(err)
		}
		payload := []byte("mux payload " + string(rune('A'+i)))
		if _, err := local.Write(payload); err != nil {
			_ = local.Close()
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(local, received); err != nil {
			_ = local.Close()
			t.Fatal(err)
		}
		if !bytes.Equal(received, payload) {
			t.Fatalf("mux payload %d mismatch", i)
		}
		_ = local.Close()
	}
	cancel()
	waitServeResult(t, "server", serverDone)
	waitServeResult(t, "client", clientDone)
	for i := 0; i < 2; i++ {
		select {
		case err := <-echoDone:
			if err != nil {
				t.Fatalf("echo server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("echo server did not finish")
		}
	}
}

func TestUDPForwardingEndToEnd(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, peer, err := echo.ReadFromUDP(buffer)
		if err == nil {
			_, err = echo.WriteToUDP(buffer[:n], peer)
		}
		echoDone <- err
	}()

	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := tunnel.NewReplayGuard(128, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	codec := testCodecConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	target := echo.LocalAddr().String()
	go func() {
		serverDone <- ServeServer(ctx, serverListener, ServerConfig{
			Tunnel:      tunnel.Config{Codec: codec, ReplayGuard: guard},
			Mux:         true,
			UDP:         true,
			AllowTarget: func(address string) bool { return address == target },
		})
	}()
	go func() {
		clientDone <- ServeUDPClient(ctx, clientUDP, ClientConfig{
			Tunnel:        tunnel.Config{Codec: codec},
			Mux:           true,
			UDP:           true,
			ServerAddress: serverListener.Addr().String(),
			TargetAddress: target,
		}, nil)
	}()

	local, err := net.DialUDP("udp", nil, clientUDP.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if err := local.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("uot loopback")
	if _, err := local.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(local, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("UDP payload = %q, want %q", received, payload)
	}
	cancel()
	waitServeResult(t, "server", serverDone)
	waitServeResult(t, "client", clientDone)
	select {
	case err := <-echoDone:
		if err != nil {
			t.Fatalf("UDP echo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UDP echo did not finish")
	}
}

func TestServerTargetPolicyRejectsBeforeDial(t *testing.T) {
	serverListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := tunnel.NewReplayGuard(16, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &countingDialer{}
	codec := testCodecConfig()
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	go func() {
		serverDone <- ServeServer(ctx, serverListener, ServerConfig{
			Tunnel: tunnel.Config{
				Codec:        codec,
				MaxClockSkew: time.Minute,
				ReplayGuard:  guard,
			},
			Dialer:      dialer,
			AllowTarget: func(string) bool { return false },
		})
	}()
	go func() {
		clientDone <- ServeClient(ctx, clientListener, ClientConfig{
			Tunnel: tunnel.Config{
				Codec:        codec,
				MaxClockSkew: time.Minute,
			},
			ServerAddress: serverListener.Addr().String(),
			TargetAddress: "example.com:443",
		})
	}()

	local, err := net.Dial("tcp", clientListener.Addr().String())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := local.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := local.Read(buffer); err == nil {
		t.Fatal("rejected forwarding connection remained open")
	}
	_ = local.Close()
	if dialer.Count() != 0 {
		t.Fatalf("target dial count = %d", dialer.Count())
	}
	cancel()
	waitServeResult(t, "server", serverDone)
	waitServeResult(t, "client", clientDone)
}

func TestServeConfigurationValidation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := ServeClient(context.Background(), listener, ClientConfig{}); err == nil {
		t.Fatal("invalid client config accepted")
	}
}

func testCodecConfig() enigma.Config {
	return enigma.Config{
		Key:             bytes.Repeat([]byte{0x39}, 32),
		MinPadding:      2,
		MaxPadding:      16,
		MinCoverPadding: 2,
		MaxCoverPadding: 16,
		MaxPayload:      1024,
	}
}

func waitServeResult(t *testing.T, name string, result <-chan error) {
	t.Helper()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("%s serve: %v", name, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s serve did not stop", name)
	}
}

type countingDialer struct {
	mu    sync.Mutex
	count int
}

func (d *countingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	d.count++
	d.mu.Unlock()
	return nil, net.ErrClosed
}

func (d *countingDialer) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.count
}
