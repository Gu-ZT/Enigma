package enigma

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func testConfig(keyByte byte) Config {
	return Config{
		Key:             bytes.Repeat([]byte{keyByte}, 32),
		MinPadding:      3,
		MaxPadding:      19,
		MinCoverPadding: 2,
		MaxCoverPadding: 17,
		MaxPayload:      128,
	}
}

func TestConnFullDuplexAndMultiFrame(t *testing.T) {
	rawA, rawB := net.Pipe()
	defer rawA.Close()
	defer rawB.Close()
	a, err := NewConn(rawA, testConfig(0x31))
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewConn(rawB, testConfig(0x31))
	if err != nil {
		t.Fatal(err)
	}

	payloadA := makePattern(4097, 7)
	payloadB := makePattern(3073, 91)
	receivedA := make([]byte, len(payloadB))
	receivedB := make([]byte, len(payloadA))

	if err := rawA.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := rawB.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	results := make(chan error, 4)
	go func() {
		_, err := io.ReadFull(a, receivedA)
		results <- err
	}()
	go func() {
		_, err := io.ReadFull(b, receivedB)
		results <- err
	}()
	go func() {
		n, err := a.Write(payloadA)
		if err == nil && n != len(payloadA) {
			err = fmt.Errorf("A wrote %d bytes", n)
		}
		results <- err
	}()
	go func() {
		n, err := b.Write(payloadB)
		if err == nil && n != len(payloadB) {
			err = fmt.Errorf("B wrote %d bytes", n)
		}
		results <- err
	}()
	for i := 0; i < 4; i++ {
		if err := <-results; err != nil {
			t.Fatalf("duplex operation: %v", err)
		}
	}
	if !bytes.Equal(receivedA, payloadB) {
		t.Fatal("A received the wrong payload")
	}
	if !bytes.Equal(receivedB, payloadA) {
		t.Fatal("B received the wrong payload")
	}
}

func TestConnSmallReadsDrainAuthenticatedRecord(t *testing.T) {
	wire := encodePayload(t, testConfig(0x52), makePattern(511, 3))
	reader := newMemoryConn(wire)
	conn, err := NewConn(reader, testConfig(0x52))
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	buffer := make([]byte, 7)
	for output.Len() < 511 {
		n, err := conn.Read(buffer)
		if err != nil {
			t.Fatalf("Read after %d bytes: %v", output.Len(), err)
		}
		if n == 0 {
			t.Fatal("Read returned no progress")
		}
		output.Write(buffer[:n])
	}
	if !bytes.Equal(output.Bytes(), makePattern(511, 3)) {
		t.Fatal("small-read payload mismatch")
	}
}

func TestConnRejectsTamperedCiphertext(t *testing.T) {
	cfg := testConfig(0x63)
	cfg.MinCoverPadding = 0
	cfg.MaxCoverPadding = 0
	wire := encodePayload(t, cfg, []byte("authenticated payload"))
	last := len(wire) - 1
	index := bytes.IndexByte([]byte(defaultCoverAlphabet), wire[last])
	if index < 0 {
		t.Fatalf("last wire byte is not a cover symbol")
	}
	wire[last] = defaultCoverAlphabet[(index+1)%len(defaultCoverAlphabet)]

	conn, err := NewConn(newMemoryConn(wire), cfg)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, err := conn.Read(buffer)
	if n != 0 {
		t.Fatalf("returned %d unauthenticated bytes", n)
	}
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered record error = %v", err)
	}
}

func TestConnRejectsWrongKeyAndTruncation(t *testing.T) {
	cfg := testConfig(0x74)
	cfg.MinCoverPadding = 0
	cfg.MaxCoverPadding = 0
	wire := encodePayload(t, cfg, []byte("secret"))

	wrong, err := NewConn(newMemoryConn(wire), testConfig(0x75))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := wrong.Read(make([]byte, 32)); err == nil || n != 0 {
		t.Fatalf("wrong key returned n=%d err=%v", n, err)
	}

	truncated, err := NewConn(newMemoryConn(wire[:len(wire)-1]), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := truncated.Read(make([]byte, 32)); err == nil || n != 0 {
		t.Fatalf("truncated stream returned n=%d err=%v", n, err)
	}
}

func TestConnRejectsUnexpectedCoverByte(t *testing.T) {
	cfg := testConfig(0x16)
	conn, err := NewConn(newMemoryConn([]byte{0x00}), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrUnexpectedCoverByte) {
		t.Fatalf("unexpected cover error = %v", err)
	}
}

func TestConnRejectsInvalidLengthBeforeReadingBody(t *testing.T) {
	cfg := Config{
		Key:        bytes.Repeat([]byte{0x27}, 32),
		MaxPayload: 64,
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var salt [sessionSaltSize]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	session, err := newSession(normalized.master, salt)
	if err != nil {
		t.Fatal(err)
	}

	maximum := innerHeaderSize + normalized.maxPayload + normalized.maxPadding + session.aead.Overhead()
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(maximum+1))
	maskLength(header, session.lengthKey, 0)
	machine := session.rotors.machineFor(0)
	machine.transform(header)

	codec, err := newCoverCodec(normalized.coverAlphabet, normalized.paddingAlphabet)
	if err != nil {
		t.Fatal(err)
	}
	encodedSalt, err := codec.encode(salt[:], 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader, err := codec.encode(header, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire := append(encodedSalt, encodedHeader...)

	conn, err := NewConn(newMemoryConn(wire), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("invalid length returned n=%d err=%v", n, err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("terminal invalid length returned n=%d err=%v", n, err)
	}
}

func TestConnZeroLengthOperations(t *testing.T) {
	conn, err := NewConn(newMemoryConn(nil), testConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(nil); n != 0 || err != nil {
		t.Fatalf("Write(nil) = %d, %v", n, err)
	}
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v", n, err)
	}
}

func encodePayload(t *testing.T, cfg Config, payload []byte) []byte {
	t.Helper()
	transport := newMemoryConn(nil)
	conn, err := NewConn(transport, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	return transport.BytesCopy()
}

func makePattern(size int, offset byte) []byte {
	result := make([]byte, size)
	for i := range result {
		result[i] = byte(i) + offset
	}
	return result
}

type memoryConn struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	closed bool
}

func newMemoryConn(initial []byte) *memoryConn {
	c := &memoryConn{}
	_, _ = c.buffer.Write(initial)
	return c
}

func (c *memoryConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffer.Read(p)
}

func (c *memoryConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return c.buffer.Write(p)
}

func (c *memoryConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *memoryConn) LocalAddr() net.Addr              { return memoryAddr("local") }
func (c *memoryConn) RemoteAddr() net.Addr             { return memoryAddr("remote") }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func (c *memoryConn) BytesCopy() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buffer.Bytes()...)
}

type memoryAddr string

func (a memoryAddr) Network() string { return "memory" }
func (a memoryAddr) String() string  { return string(a) }

var _ net.Conn = (*memoryConn)(nil)
