// Package transport contains optional connection wrappers that sit below
// ETPH/1. They do not change ETP/1 records or provide authentication by
// themselves.
package transport

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const defaultMaxHTTPHeader = 16 * 1024

var (
	// ErrHTTPProtocol indicates a malformed or unexpected camouflage exchange.
	ErrHTTPProtocol = errors.New("transport: invalid HTTP camouflage")
	// ErrTLSConfig indicates that a TLS wrapper was requested without enough
	// configuration to perform a handshake.
	ErrTLSConfig = errors.New("transport: invalid TLS configuration")
)

// HTTPConfig controls the small HTTP/1.1 prelude used before ETPH/1.
type HTTPConfig struct {
	Host      string
	Path      string
	MaxHeader int
}

func (cfg HTTPConfig) normalize() (HTTPConfig, error) {
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if !strings.HasPrefix(cfg.Path, "/") || strings.ContainsAny(cfg.Path, "\r\n") {
		return HTTPConfig{}, fmt.Errorf("%w: invalid path", ErrHTTPProtocol)
	}
	if strings.ContainsAny(cfg.Host, "\r\n") {
		return HTTPConfig{}, fmt.Errorf("%w: invalid host", ErrHTTPProtocol)
	}
	if cfg.MaxHeader == 0 {
		cfg.MaxHeader = defaultMaxHTTPHeader
	}
	if cfg.MaxHeader < 256 || cfg.MaxHeader > 1<<20 {
		return HTTPConfig{}, fmt.Errorf("%w: MaxHeader must be between 256 and %d", ErrHTTPProtocol, 1<<20)
	}
	return cfg, nil
}

// ClientHTTP writes an HTTP request, waits for a 2xx response, and returns a
// connection that preserves any bytes buffered after the response headers.
func ClientHTTP(raw net.Conn, cfg HTTPConfig) (net.Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("transport: nil connection")
	}
	normalized, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	host := normalized.Host
	if host == "" {
		host = "localhost"
	}
	request := "POST " + normalized.Path + " HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
	if err := writeFull(raw, []byte(request)); err != nil {
		return nil, fmt.Errorf("transport: write HTTP camouflage: %w", err)
	}
	reader := bufio.NewReader(raw)
	status, headers, err := readHeaders(reader, normalized.MaxHeader)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(status, "HTTP/1.") {
		return nil, fmt.Errorf("%w: response version", ErrHTTPProtocol)
	}
	fields := strings.Fields(status)
	if len(fields) < 2 {
		return nil, fmt.Errorf("%w: response status", ErrHTTPProtocol)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil || code < 200 || code >= 300 {
		return nil, fmt.Errorf("%w: response status %q", ErrHTTPProtocol, status)
	}
	if value := strings.ToLower(headers["content-length"]); value != "" && value != "0" {
		return nil, fmt.Errorf("%w: response body is not empty", ErrHTTPProtocol)
	}
	return &bufferedConn{Conn: raw, reader: reader}, nil
}

// ServerHTTP reads and validates one HTTP request, sends a 200 response, and
// returns a connection that preserves ETPH/1 bytes already buffered.
func ServerHTTP(raw net.Conn, cfg HTTPConfig) (net.Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("transport: nil connection")
	}
	normalized, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(raw)
	requestLine, headers, err := readHeaders(reader, normalized.MaxHeader)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(requestLine)
	if len(fields) != 3 || fields[0] != "POST" || fields[1] != normalized.Path || fields[2] != "HTTP/1.1" {
		return nil, fmt.Errorf("%w: request line", ErrHTTPProtocol)
	}
	if normalized.Host != "" && !strings.EqualFold(headers["host"], normalized.Host) {
		return nil, fmt.Errorf("%w: host mismatch", ErrHTTPProtocol)
	}
	if value := strings.ToLower(headers["content-length"]); value != "" && value != "0" {
		return nil, fmt.Errorf("%w: request body is not empty", ErrHTTPProtocol)
	}
	if headers["transfer-encoding"] != "" {
		return nil, fmt.Errorf("%w: transfer encoding is not allowed", ErrHTTPProtocol)
	}
	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
	if err := writeFull(raw, []byte(response)); err != nil {
		return nil, fmt.Errorf("transport: write HTTP response: %w", err)
	}
	return &bufferedConn{Conn: raw, reader: reader}, nil
}

// ClientTLS upgrades raw with a client TLS handshake. The caller controls
// certificate verification through cfg; insecure verification must be an
// explicit caller choice.
func ClientTLS(raw net.Conn, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	if raw == nil || cfg == nil {
		return nil, ErrTLSConfig
	}
	conn := tls.Client(raw, cfg.Clone())
	if err := handshakeTLS(conn, timeout); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// ServerTLS upgrades raw with a server TLS handshake using cfg certificates or
// callbacks.
func ServerTLS(raw net.Conn, cfg *tls.Config, timeout time.Duration) (net.Conn, error) {
	if raw == nil || cfg == nil {
		return nil, ErrTLSConfig
	}
	conn := tls.Server(raw, cfg.Clone())
	if err := handshakeTLS(conn, timeout); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func handshakeTLS(conn *tls.Conn, timeout time.Duration) error {
	if timeout < 0 {
		return fmt.Errorf("%w: negative timeout", ErrTLSConfig)
	}
	if timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("transport: set TLS deadline: %w", err)
		}
	}
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("transport: TLS handshake: %w", err)
	}
	if timeout > 0 {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return fmt.Errorf("transport: clear TLS deadline: %w", err)
		}
	}
	return nil
}

func readHeaders(reader *bufio.Reader, limit int) (string, map[string]string, error) {
	var data []byte
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return "", nil, fmt.Errorf("transport: read HTTP headers: %w", err)
		}
		data = append(data, line...)
		if len(data) > limit {
			return "", nil, fmt.Errorf("%w: headers exceed limit", ErrHTTPProtocol)
		}
		if bytesTrimSpace(line) == 0 {
			break
		}
	}
	lines := strings.Split(string(data), "\r\n")
	if len(lines) < 2 || lines[len(lines)-1] != "" || lines[0] == "" {
		return "", nil, fmt.Errorf("%w: header termination", ErrHTTPProtocol)
	}
	headers := make(map[string]string, len(lines)-2)
	for _, line := range lines[1 : len(lines)-1] {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) == "" {
			return "", nil, fmt.Errorf("%w: malformed header", ErrHTTPProtocol)
		}
		headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return lines[0], headers, nil
}

func bytesTrimSpace(value []byte) int {
	return len(strings.TrimSpace(string(value)))
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
