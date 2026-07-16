package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"Enigma/pkg/enigma"
)

func TestHandshakeDerivesMatchingUniqueKeys(t *testing.T) {
	firstClient, firstServer := runKeyHandshake(t, 0x41)
	if !bytes.Equal(firstClient, firstServer) {
		t.Fatal("client and server session keys differ")
	}
	secondClient, secondServer := runKeyHandshake(t, 0x41)
	if !bytes.Equal(secondClient, secondServer) {
		t.Fatal("second client and server session keys differ")
	}
	if bytes.Equal(firstClient, secondClient) {
		t.Fatal("independent handshakes produced the same session key")
	}
}

func TestHandshakePacketSizes(t *testing.T) {
	if clientPacketSize != 86 {
		t.Fatalf("client packet size = %d", clientPacketSize)
	}
	if serverPacketSize != 94 {
		t.Fatalf("server packet size = %d", serverPacketSize)
	}
}

func TestTunnelConnFullDuplex(t *testing.T) {
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()
	guard, err := NewReplayGuard(128, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	clientConfig := testTunnelConfig(0x52, nil, now)
	serverConfig := testTunnelConfig(0x52, guard, now)

	type serverResult struct {
		conn *enigma.Conn
		err  error
	}
	serverReady := make(chan serverResult, 1)
	go func() {
		conn, err := NewServerConn(rawServer, serverConfig)
		serverReady <- serverResult{conn: conn, err: err}
	}()
	client, err := NewClientConn(rawClient, clientConfig)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	result := <-serverReady
	if result.err != nil {
		t.Fatalf("server handshake: %v", result.err)
	}
	server := result.conn

	clientPayload := bytes.Repeat([]byte("client-to-server"), 257)
	serverPayload := bytes.Repeat([]byte("server-to-client"), 193)
	clientReceived := make([]byte, len(serverPayload))
	serverReceived := make([]byte, len(clientPayload))
	results := make(chan error, 4)
	go func() {
		_, err := io.ReadFull(client, clientReceived)
		results <- err
	}()
	go func() {
		_, err := io.ReadFull(server, serverReceived)
		results <- err
	}()
	go func() {
		_, err := client.Write(clientPayload)
		results <- err
	}()
	go func() {
		_, err := server.Write(serverPayload)
		results <- err
	}()
	for i := 0; i < 4; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(clientReceived, serverPayload) {
		t.Fatal("client received incorrect payload")
	}
	if !bytes.Equal(serverReceived, clientPayload) {
		t.Fatal("server received incorrect payload")
	}
}

func TestClientHelloAuthenticationClockAndReplay(t *testing.T) {
	psk := bytes.Repeat([]byte{0x63}, 32)
	now := time.Unix(10_000, 0)
	state, err := buildClientHello(psk, now)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewReplayGuard(16, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acceptClientHello(psk, state.packet, now, time.Minute, guard); err != nil {
		t.Fatalf("accept valid hello: %v", err)
	}
	if _, err := acceptClientHello(psk, state.packet, now, time.Minute, guard); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v", err)
	}

	tampered := state.packet
	tampered[len(tampered)-1] ^= 1
	otherGuard, err := NewReplayGuard(16, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acceptClientHello(psk, tampered, now, time.Minute, otherGuard); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}

	oldState, err := buildClientHello(psk, now.Add(-2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acceptClientHello(psk, oldState.packet, now, time.Minute, otherGuard); !errors.Is(err, ErrClockSkew) {
		t.Fatalf("clock skew error = %v", err)
	}
}

func TestTunnelRejectsWrongKey(t *testing.T) {
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	guard, err := NewReplayGuard(16, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	serverDone := make(chan error, 1)
	go func() {
		_, err := NewServerConn(rawServer, testTunnelConfig(0x71, guard, now))
		_ = rawServer.Close()
		serverDone <- err
	}()
	if _, err := NewClientConn(rawClient, testTunnelConfig(0x72, nil, now)); err == nil {
		t.Fatal("wrong-key client handshake succeeded")
	}
	if err := <-serverDone; !errors.Is(err, ErrAuthentication) {
		t.Fatalf("server error = %v", err)
	}
}

func TestTunnelConfigValidation(t *testing.T) {
	now := time.Unix(1, 0)
	valid := testTunnelConfig(1, nil, now)
	if _, err := normalizeConfig(valid, false); err != nil {
		t.Fatalf("valid client config: %v", err)
	}
	if _, err := normalizeConfig(valid, true); err == nil {
		t.Fatal("server config without replay guard accepted")
	}
	valid.HandshakeTimeout = -time.Second
	if _, err := normalizeConfig(valid, false); err == nil {
		t.Fatal("negative handshake timeout accepted")
	}
	valid = testTunnelConfig(1, nil, now)
	valid.MaxClockSkew = maxClockSkewLimit + time.Second
	if _, err := normalizeConfig(valid, false); err == nil {
		t.Fatal("excessive clock skew accepted")
	}
	shortGuard, err := NewReplayGuard(1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	valid = testTunnelConfig(1, shortGuard, now)
	if _, err := normalizeConfig(valid, true); err == nil {
		t.Fatal("short replay TTL accepted")
	}
}

func runKeyHandshake(t *testing.T, keyByte byte) ([]byte, []byte) {
	t.Helper()
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()
	guard, err := NewReplayGuard(16, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	clientConfig, err := normalizeConfig(testTunnelConfig(keyByte, nil, now), false)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := normalizeConfig(testTunnelConfig(keyByte, guard, now), true)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		key, err := serverHandshake(rawServer, serverConfig)
		serverKey <- key
		serverErr <- err
	}()
	clientKey, err := clientHandshake(rawClient, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	return clientKey, <-serverKey
}

func testTunnelConfig(keyByte byte, guard *ReplayGuard, now time.Time) Config {
	return Config{
		Codec: enigma.Config{
			Key:             bytes.Repeat([]byte{keyByte}, 32),
			MinPadding:      2,
			MaxPadding:      16,
			MinCoverPadding: 2,
			MaxCoverPadding: 16,
			MaxPayload:      512,
		},
		HandshakeTimeout: 2 * time.Second,
		MaxClockSkew:     time.Minute,
		ReplayGuard:      guard,
		now:              func() time.Time { return now },
	}
}
