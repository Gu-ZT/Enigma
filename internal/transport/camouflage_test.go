package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestHTTPHandshakePreservesStream(t *testing.T) {
	left, right := net.Pipe()
	serverDone := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := ServerHTTP(right, HTTPConfig{Host: "example.test", Path: "/etp"})
		serverDone <- struct {
			conn net.Conn
			err  error
		}{conn, err}
	}()
	client, err := ClientHTTP(left, HTTPConfig{Host: "example.test", Path: "/etp"})
	if err != nil {
		t.Fatal(err)
	}
	serverResult := <-serverDone
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	defer client.Close()
	defer serverResult.conn.Close()

	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("etph-after-http"))
		writeDone <- err
	}()
	buffer := make([]byte, len("etph-after-http"))
	if _, err := serverResult.conn.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "etph-after-http" {
		t.Fatalf("payload = %q", buffer)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPHandshakeRejectsUnexpectedRequest(t *testing.T) {
	left, right := net.Pipe()
	result := make(chan error, 1)
	go func() {
		_, err := ServerHTTP(right, HTTPConfig{Host: "example.test", Path: "/etp"})
		result <- err
	}()
	_, _ = left.Write([]byte("GET /wrong HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	if err := <-result; err == nil {
		t.Fatal("unexpected request accepted")
	}
	_ = left.Close()
	_ = right.Close()
}

func TestTLSHandshake(t *testing.T) {
	serverConfig, clientConfig := testTLSConfigs(t)
	left, right := net.Pipe()
	serverDone := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, err := ServerTLS(right, serverConfig, time.Second)
		serverDone <- struct {
			conn net.Conn
			err  error
		}{conn, err}
	}()
	client, err := ClientTLS(left, clientConfig, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	serverResult := <-serverDone
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	defer client.Close()
	defer serverResult.conn.Close()
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("tls-etph"))
		writeDone <- err
	}()
	buffer := make([]byte, 8)
	if _, err := serverResult.conn.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "tls-etph" {
		t.Fatalf("TLS payload = %q", buffer)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestTLSConfigValidation(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, err := ClientTLS(left, nil, 0); err == nil {
		t.Fatal("nil client TLS config accepted")
	}
	if _, err := ServerTLS(right, nil, 0); err == nil {
		t.Fatal("nil server TLS config accepted")
	}
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, &tls.Config{
		ServerName:         "example.test",
		InsecureSkipVerify: true, // test-only self-signed certificate
		MinVersion:         tls.VersionTLS13,
	}
}
