package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"Enigma/internal/tunnel"
)

const (
	socks5Version = 5
	socks5NoAuth  = 0

	socks5ReplySucceeded          = 0
	socks5ReplyGeneralFailure     = 1
	socks5ReplyCommandUnsupported = 7
	socks5ReplyConnectionRefused  = 5
)

var errSOCKS5NoAcceptableMethod = errors.New("app: SOCKS5 has no acceptable authentication method")

// SOCKS5Selector performs the no-auth SOCKS5 greeting and CONNECT request,
// returning a target selection whose response is sent after remote dialing.
func SOCKS5Selector(conn net.Conn) (TargetSelection, error) {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return TargetSelection{}, fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if greeting[0] != socks5Version || greeting[1] == 0 {
		return TargetSelection{}, fmt.Errorf("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return TargetSelection{}, fmt.Errorf("read SOCKS5 methods: %w", err)
	}
	foundNoAuth := false
	for _, method := range methods {
		if method == socks5NoAuth {
			foundNoAuth = true
			break
		}
	}
	if !foundNoAuth {
		_ = writeFull(conn, []byte{socks5Version, 0xff})
		return TargetSelection{}, errSOCKS5NoAcceptableMethod
	}
	if err := writeFull(conn, []byte{socks5Version, socks5NoAuth}); err != nil {
		return TargetSelection{}, fmt.Errorf("write SOCKS5 method: %w", err)
	}

	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return TargetSelection{}, fmt.Errorf("read SOCKS5 request: %w", err)
	}
	if request[0] != socks5Version {
		return TargetSelection{}, fmt.Errorf("invalid SOCKS5 request version")
	}
	if request[1] != 1 {
		_ = writeSOCKS5Reply(conn, socks5ReplyCommandUnsupported)
		return TargetSelection{}, fmt.Errorf("SOCKS5 command %d is unsupported", request[1])
	}
	if request[2] != 0 {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneralFailure)
		return TargetSelection{}, fmt.Errorf("invalid SOCKS5 reserved byte")
	}
	host, err := readSOCKS5Address(conn, request[3])
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneralFailure)
		return TargetSelection{}, err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return TargetSelection{}, fmt.Errorf("read SOCKS5 port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneralFailure)
		return TargetSelection{}, fmt.Errorf("SOCKS5 target port is zero")
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if err := tunnel.ValidateTargetAddress(address); err != nil {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneralFailure)
		return TargetSelection{}, err
	}
	responded := false
	return TargetSelection{
		Address: address,
		Respond: func(err error) error {
			if responded {
				return fmt.Errorf("SOCKS5 response already sent")
			}
			responded = true
			if err == nil {
				return writeSOCKS5Reply(conn, socks5ReplySucceeded)
			}
			code := byte(socks5ReplyGeneralFailure)
			if errors.Is(err, tunnel.ErrTargetRejected) {
				code = socks5ReplyConnectionRefused
			}
			return writeSOCKS5Reply(conn, code)
		},
	}, nil
}

func readSOCKS5Address(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case 1:
		var value [4]byte
		if _, err := io.ReadFull(reader, value[:]); err != nil {
			return "", fmt.Errorf("read SOCKS5 IPv4 address: %w", err)
		}
		return net.IP(value[:]).String(), nil
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", fmt.Errorf("read SOCKS5 domain length: %w", err)
		}
		if length[0] == 0 {
			return "", fmt.Errorf("SOCKS5 domain is empty")
		}
		host := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, host); err != nil {
			return "", fmt.Errorf("read SOCKS5 domain: %w", err)
		}
		return string(host), nil
	case 4:
		var value [16]byte
		if _, err := io.ReadFull(reader, value[:]); err != nil {
			return "", fmt.Errorf("read SOCKS5 IPv6 address: %w", err)
		}
		return net.IP(value[:]).String(), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS5 address type %d", addressType)
	}
}

func writeSOCKS5Reply(conn io.Writer, reply byte) error {
	response := []byte{socks5Version, reply, 0, 1, 0, 0, 0, 0, 0, 0}
	return writeFull(conn, response)
}

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
