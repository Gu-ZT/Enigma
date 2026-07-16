package app

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"Enigma/internal/tunnel"
)

const maxHTTPConnectHeader = 16 * 1024

var errHTTPConnectRequest = errors.New("app: invalid HTTP CONNECT request")

// HTTPConnectSelector parses one HTTP/1.x CONNECT request and delays the HTTP
// response until the remote target has been opened.
func HTTPConnectSelector(conn net.Conn) (TargetSelection, error) {
	request, err := readHTTPConnectHeader(conn)
	if err != nil {
		return TargetSelection{}, err
	}
	lines := strings.Split(string(request), "\r\n")
	if len(lines) < 2 {
		_ = writeHTTPConnectFailure(conn, 400)
		return TargetSelection{}, errHTTPConnectRequest
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 3 || !strings.EqualFold(parts[0], "CONNECT") || !strings.HasPrefix(parts[2], "HTTP/1.") {
		_ = writeHTTPConnectFailure(conn, 405)
		return TargetSelection{}, fmt.Errorf("%w: method or HTTP version", errHTTPConnectRequest)
	}
	if err := tunnel.ValidateTargetAddress(parts[1]); err != nil {
		_ = writeHTTPConnectFailure(conn, 400)
		return TargetSelection{}, fmt.Errorf("%w: %v", errHTTPConnectRequest, err)
	}
	responded := false
	return TargetSelection{
		Address: parts[1],
		Respond: func(err error) error {
			if responded {
				return fmt.Errorf("HTTP CONNECT response already sent")
			}
			responded = true
			if err != nil {
				return writeHTTPConnectFailure(conn, 502)
			}
			return writeFull(conn, []byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		},
	}, nil
}

func readHTTPConnectHeader(conn net.Conn) ([]byte, error) {
	buffer := make([]byte, 0, 1024)
	var last [4]byte
	for len(buffer) < maxHTTPConnectHeader {
		var one [1]byte
		n, err := conn.Read(one[:])
		if err != nil {
			return nil, fmt.Errorf("read HTTP CONNECT header: %w", err)
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
		buffer = append(buffer, one[0])
		last[0], last[1], last[2], last[3] = last[1], last[2], last[3], one[0]
		if string(last[:]) == "\r\n\r\n" {
			return buffer, nil
		}
	}
	_ = writeHTTPConnectFailure(conn, 431)
	return nil, fmt.Errorf("%w: header too large", errHTTPConnectRequest)
}

func writeHTTPConnectFailure(conn io.Writer, status int) error {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, httpStatusText(status))
	return writeFull(conn, []byte(response))
}

func httpStatusText(status int) string {
	switch status {
	case 400:
		return "Bad Request"
	case 405:
		return "Method Not Allowed"
	case 431:
		return "Request Header Fields Too Large"
	case 502:
		return "Bad Gateway"
	default:
		return "Error"
	}
}
