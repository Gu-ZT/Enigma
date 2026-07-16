// Package uot implements a bounded UDP-over-reliable-stream packet layer.
// Packets are intended to be carried inside an authenticated ETP connection or
// a mux logical stream; this package does not provide authentication itself.
package uot

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	protocolVersion  = 1
	headerSize       = 8
	maxAddress       = 512
	defaultMaxPacket = 65535
)

var (
	// ErrProtocol indicates a malformed UoT packet frame.
	ErrProtocol = errors.New("uot: invalid packet frame")
	// ErrClosed indicates that the packet stream is closed.
	ErrClosed = errors.New("uot: connection closed")
)

// Config bounds packet payload allocation and address length.
type Config struct {
	MaxPacket int
}

// Conn carries address-bearing datagrams over one ordered reliable connection.
// It implements net.PacketConn semantics except that LocalAddr is inherited
// from the underlying connection and packet delivery is stream-ordered.
type Conn struct {
	raw       net.Conn
	br        *bufio.Reader
	maxPacket int

	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
	errMu     sync.Mutex
	err       error
}

// NewConn wraps raw with UoT packet framing.
func NewConn(raw net.Conn, cfg Config) (*Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("uot: nil connection")
	}
	maxPacket := cfg.MaxPacket
	if maxPacket == 0 {
		maxPacket = defaultMaxPacket
	}
	if maxPacket < 1 || maxPacket > 65535 {
		return nil, fmt.Errorf("uot: MaxPacket must be between 1 and 65535")
	}
	return &Conn{raw: raw, br: bufio.NewReader(raw), maxPacket: maxPacket, closed: make(chan struct{})}, nil
}

// ReadFrom reads one packet and its source address.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var header [headerSize]byte
	if _, err := io.ReadFull(c.br, header[:]); err != nil {
		return 0, nil, c.fail(fmt.Errorf("uot: read header: %w", err))
	}
	if header[0] != protocolVersion || header[1] != 0 {
		return 0, nil, c.fail(fmt.Errorf("%w: version or flags", ErrProtocol))
	}
	addressLen := int(binary.BigEndian.Uint16(header[2:4]))
	payloadLen := int(binary.BigEndian.Uint32(header[4:8]))
	if addressLen < 1 || addressLen > maxAddress || payloadLen > c.maxPacket {
		return 0, nil, c.fail(fmt.Errorf("%w: address %d payload %d", ErrProtocol, addressLen, payloadLen))
	}
	address := make([]byte, addressLen)
	if _, err := io.ReadFull(c.br, address); err != nil {
		return 0, nil, c.fail(fmt.Errorf("uot: read address: %w", err))
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, c.fail(fmt.Errorf("uot: read payload: %w", err))
	}
	n := copy(p, payload)
	if n < len(payload) {
		return n, packetAddr(string(address)), io.ErrShortBuffer
	}
	return n, packetAddr(string(address)), nil
}

// WriteTo writes one packet and its destination address.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > c.maxPacket {
		return 0, fmt.Errorf("uot: packet length %d exceeds %d", len(p), c.maxPacket)
	}
	if addr == nil || addr.String() == "" || len(addr.String()) > maxAddress {
		return 0, fmt.Errorf("uot: invalid packet address")
	}
	address := []byte(addr.String())
	header := [headerSize]byte{protocolVersion, 0}
	binary.BigEndian.PutUint16(header[2:4], uint16(len(address)))
	binary.BigEndian.PutUint32(header[4:8], uint32(len(p)))
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.errIfClosed(); err != nil {
		return 0, err
	}
	if err := writeFull(c.rawConn(), header[:]); err != nil {
		return 0, c.fail(fmt.Errorf("uot: write header: %w", err))
	}
	if err := writeFull(c.rawConn(), address); err != nil {
		return 0, c.fail(fmt.Errorf("uot: write address: %w", err))
	}
	if err := writeFull(c.rawConn(), p); err != nil {
		return 0, c.fail(fmt.Errorf("uot: write payload: %w", err))
	}
	return len(p), nil
}

func (c *Conn) rawConn() net.Conn { return c.raw }

// Close closes the underlying reliable connection.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.errMu.Lock()
		c.err = ErrClosed
		c.errMu.Unlock()
		close(c.closed)
		_ = c.rawConn().Close()
	})
	return nil
}

func (c *Conn) fail(err error) error {
	c.closeOnce.Do(func() {
		c.errMu.Lock()
		c.err = err
		c.errMu.Unlock()
		close(c.closed)
		_ = c.rawConn().Close()
	})
	return err
}

func (c *Conn) errIfClosed() error {
	select {
	case <-c.closed:
		c.errMu.Lock()
		defer c.errMu.Unlock()
		if c.err != nil {
			return c.err
		}
		return ErrClosed
	default:
		return nil
	}
}

func (c *Conn) LocalAddr() net.Addr                { return c.rawConn().LocalAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.rawConn().SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.rawConn().SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.rawConn().SetWriteDeadline(t) }

type packetAddr string

// NewAddr returns an address value suitable for WriteTo. The address is kept
// as text so domain targets do not require local DNS resolution.
func NewAddr(address string) net.Addr { return packetAddr(address) }

func (a packetAddr) Network() string { return "udp" }
func (a packetAddr) String() string  { return string(a) }

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
