package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	targetProtocolVersion = 1
	targetCommandConnect  = 1

	targetStatusOK       = 0
	targetStatusRejected = 1

	maxTargetAddress  = 512
	maxResponseReason = 512
)

var (
	// ErrTargetProtocol indicates a malformed target negotiation message.
	ErrTargetProtocol = errors.New("tunnel: invalid target message")
	// ErrTargetRejected indicates that the server could not open the requested target.
	ErrTargetRejected = errors.New("tunnel: target rejected")
)

// ValidateTargetAddress checks that address is a canonical host:port target.
func ValidateTargetAddress(address string) error {
	normalized, err := normalizeTargetAddress(address)
	if err != nil {
		return err
	}
	if normalized != address {
		return fmt.Errorf("tunnel: target address must be canonical as %q", normalized)
	}
	return nil
}

// OpenTarget sends a CONNECT request and waits for the server result.
func OpenTarget(conn net.Conn, address string) error {
	if conn == nil {
		return fmt.Errorf("tunnel: nil target connection")
	}
	if err := WriteTargetRequest(conn, address); err != nil {
		return err
	}
	return ReadTargetResponse(conn)
}

// WriteTargetRequest writes one CONNECT request for address.
func WriteTargetRequest(writer io.Writer, address string) error {
	normalized, err := normalizeTargetAddress(address)
	if err != nil {
		return err
	}
	header := [4]byte{targetProtocolVersion, targetCommandConnect}
	binary.BigEndian.PutUint16(header[2:], uint16(len(normalized)))
	if err := writeFull(writer, header[:]); err != nil {
		return fmt.Errorf("tunnel: write target header: %w", err)
	}
	if err := writeFull(writer, []byte(normalized)); err != nil {
		return fmt.Errorf("tunnel: write target address: %w", err)
	}
	return nil
}

// ReadTargetRequest reads and validates one CONNECT request.
func ReadTargetRequest(reader io.Reader) (string, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return "", fmt.Errorf("tunnel: read target header: %w", err)
	}
	if header[0] != targetProtocolVersion || header[1] != targetCommandConnect {
		return "", ErrTargetProtocol
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if length < 1 || length > maxTargetAddress {
		return "", fmt.Errorf("%w: address length %d", ErrTargetProtocol, length)
	}
	address := make([]byte, length)
	if _, err := io.ReadFull(reader, address); err != nil {
		return "", fmt.Errorf("tunnel: read target address: %w", err)
	}
	normalized, err := normalizeTargetAddress(string(address))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTargetProtocol, err)
	}
	if normalized != string(address) {
		return "", fmt.Errorf("%w: target address is not canonical", ErrTargetProtocol)
	}
	return normalized, nil
}

// WriteTargetResponse reports whether the requested target was opened. An
// empty reason indicates success; a non-empty reason indicates rejection.
func WriteTargetResponse(writer io.Writer, reason string) error {
	status := byte(targetStatusOK)
	if reason != "" {
		status = targetStatusRejected
	}
	if len(reason) > maxResponseReason {
		reason = reason[:maxResponseReason]
	}
	header := [4]byte{targetProtocolVersion, status}
	binary.BigEndian.PutUint16(header[2:], uint16(len(reason)))
	if err := writeFull(writer, header[:]); err != nil {
		return fmt.Errorf("tunnel: write target response header: %w", err)
	}
	if err := writeFull(writer, []byte(reason)); err != nil {
		return fmt.Errorf("tunnel: write target response reason: %w", err)
	}
	return nil
}

// ReadTargetResponse reads the server result for a CONNECT request.
func ReadTargetResponse(reader io.Reader) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("tunnel: read target response header: %w", err)
	}
	if header[0] != targetProtocolVersion {
		return ErrTargetProtocol
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if length > maxResponseReason {
		return fmt.Errorf("%w: response length %d", ErrTargetProtocol, length)
	}
	reason := make([]byte, length)
	if _, err := io.ReadFull(reader, reason); err != nil {
		return fmt.Errorf("tunnel: read target response reason: %w", err)
	}
	switch header[1] {
	case targetStatusOK:
		if length != 0 {
			return fmt.Errorf("%w: success response contains a reason", ErrTargetProtocol)
		}
		return nil
	case targetStatusRejected:
		if length == 0 {
			return ErrTargetRejected
		}
		return fmt.Errorf("%w: %s", ErrTargetRejected, reason)
	default:
		return fmt.Errorf("%w: unknown response status %d", ErrTargetProtocol, header[1])
	}
}

func normalizeTargetAddress(address string) (string, error) {
	if len(address) < 1 || len(address) > maxTargetAddress {
		return "", fmt.Errorf("tunnel: target address length must be between 1 and %d", maxTargetAddress)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("tunnel: invalid target address: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("tunnel: target host is empty")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("tunnel: invalid target port %q", portText)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
