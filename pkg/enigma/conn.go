package enigma

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
)

const innerHeaderSize = 3

type sessionState struct {
	aead        cipher.AEAD
	rotors      rotorSet
	lengthKey   [32]byte
	noncePrefix [4]byte
}

// Conn is an authenticated, Enigma-obfuscated net.Conn. One concurrent reader
// and one concurrent writer are supported. Multiple writers are serialized.
type Conn struct {
	net.Conn
	cfg normalizedConfig

	writeMu      sync.Mutex
	writeErr     error
	sendReady    bool
	sendSession  sessionState
	sendSequence uint64

	readMu        sync.Mutex
	readErr       error
	recvReady     bool
	recvSession   sessionState
	recvSequence  uint64
	reader        *bufio.Reader
	decoder       *coverCodec
	pending       []byte
	pendingOffset int

	encoder *coverCodec
}

func newConn(conn net.Conn, cfg normalizedConfig, codec *coverCodec) *Conn {
	encoder := *codec
	decoder := *codec
	encoder.half = -1
	decoder.half = -1
	return &Conn{
		Conn:    conn,
		cfg:     cfg,
		reader:  bufio.NewReaderSize(conn, 32*1024),
		encoder: &encoder,
		decoder: &decoder,
	}
}

// Write encrypts and writes p as one or more bounded ETP/1 records.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if !c.sendReady {
		if err := c.initializeSender(); err != nil {
			c.writeErr = err
			return 0, err
		}
	}

	total := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > c.cfg.maxPayload {
			chunkSize = c.cfg.maxPayload
		}
		if c.sendSequence == math.MaxUint64 {
			err := fmt.Errorf("enigma: send sequence exhausted")
			c.writeErr = err
			return total, err
		}
		if err := c.writeFrame(p[:chunkSize]); err != nil {
			c.writeErr = err
			return total, err
		}
		c.sendSequence++
		total += chunkSize
		p = p[chunkSize:]
	}
	return total, nil
}

func (c *Conn) initializeSender() error {
	var salt [sessionSaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return fmt.Errorf("enigma: generate session salt: %w", err)
	}
	session, err := newSession(c.cfg.master, salt)
	if err != nil {
		return err
	}
	encoded, err := c.encoder.encode(salt[:], c.cfg.minCoverPadding, c.cfg.maxCoverPadding)
	if err != nil {
		return err
	}
	if err := writeFull(c.Conn, encoded); err != nil {
		return fmt.Errorf("enigma: write session salt: %w", err)
	}
	c.sendSession = session
	c.sendReady = true
	return nil
}

func (c *Conn) writeFrame(payload []byte) error {
	paddingLength, err := randomRange(c.cfg.minPadding, c.cfg.maxPadding)
	if err != nil {
		return err
	}
	plaintext := make([]byte, innerHeaderSize+len(payload)+paddingLength)
	plaintext[0] = protocolVersion
	binary.BigEndian.PutUint16(plaintext[1:3], uint16(len(payload)))
	copy(plaintext[innerHeaderSize:], payload)
	if paddingLength > 0 {
		padding := plaintext[innerHeaderSize+len(payload):]
		if _, err := io.ReadFull(rand.Reader, padding); err != nil {
			return fmt.Errorf("enigma: generate record padding: %w", err)
		}
	}

	ciphertextLength := len(plaintext) + c.sendSession.aead.Overhead()
	if ciphertextLength > math.MaxUint16 {
		return fmt.Errorf("%w: ciphertext too large", ErrInvalidFrame)
	}
	length := uint16(ciphertextLength)
	aad := frameAAD(c.sendSequence, length)
	nonce := frameNonce(c.sendSession.noncePrefix, c.sendSequence)
	ciphertext := c.sendSession.aead.Seal(nil, nonce[:], plaintext, aad)

	wire := make([]byte, 2+len(ciphertext))
	binary.BigEndian.PutUint16(wire[:2], length)
	maskLength(wire[:2], c.sendSession.lengthKey, c.sendSequence)
	copy(wire[2:], ciphertext)
	machine := c.sendSession.rotors.machineFor(c.sendSequence)
	machine.transform(wire)

	encoded, err := c.encoder.encode(wire, c.cfg.minCoverPadding, c.cfg.maxCoverPadding)
	if err != nil {
		return err
	}
	if err := writeFull(c.Conn, encoded); err != nil {
		return fmt.Errorf("enigma: write frame: %w", err)
	}
	return nil
}

// Read authenticates and returns plaintext from ETP/1 records.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.pendingOffset < len(c.pending) {
		return c.drainPending(p), nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	if !c.recvReady {
		if err := c.initializeReceiver(); err != nil {
			c.readErr = err
			return 0, err
		}
	}
	if c.recvSequence == math.MaxUint64 {
		err := fmt.Errorf("enigma: receive sequence exhausted")
		c.readErr = err
		return 0, err
	}

	payload, err := c.readFrame()
	if err != nil {
		c.readErr = err
		return 0, err
	}
	c.recvSequence++
	c.pending = payload
	c.pendingOffset = 0
	return c.drainPending(p), nil
}

func (c *Conn) initializeReceiver() error {
	var salt [sessionSaltSize]byte
	if _, err := c.decoder.readFull(c.reader, salt[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return fmt.Errorf("enigma: read session salt: %w", err)
	}
	session, err := newSession(c.cfg.master, salt)
	if err != nil {
		return err
	}
	c.recvSession = session
	c.recvReady = true
	return nil
}

func (c *Conn) readFrame() ([]byte, error) {
	machine := c.recvSession.rotors.machineFor(c.recvSequence)
	var encodedLength [2]byte
	if _, err := c.decoder.readFull(c.reader, encodedLength[:]); err != nil {
		return nil, err
	}
	machine.transform(encodedLength[:])
	maskLength(encodedLength[:], c.recvSession.lengthKey, c.recvSequence)
	ciphertextLength := int(binary.BigEndian.Uint16(encodedLength[:]))
	minimum := innerHeaderSize + c.recvSession.aead.Overhead() + 1
	maximum := innerHeaderSize + c.cfg.maxPayload + c.cfg.maxPadding + c.recvSession.aead.Overhead()
	if ciphertextLength < minimum || ciphertextLength > maximum {
		return nil, fmt.Errorf("%w: ciphertext length %d outside [%d,%d]", ErrInvalidFrame, ciphertextLength, minimum, maximum)
	}

	ciphertext := make([]byte, ciphertextLength)
	if _, err := c.decoder.readFull(c.reader, ciphertext); err != nil {
		return nil, err
	}
	machine.transform(ciphertext)
	length := uint16(ciphertextLength)
	aad := frameAAD(c.recvSequence, length)
	nonce := frameNonce(c.recvSession.noncePrefix, c.recvSequence)
	plaintext, err := c.recvSession.aead.Open(ciphertext[:0], nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	if len(plaintext) < innerHeaderSize || plaintext[0] != protocolVersion {
		return nil, fmt.Errorf("%w: unsupported inner version", ErrInvalidFrame)
	}
	payloadLength := int(binary.BigEndian.Uint16(plaintext[1:3]))
	if payloadLength < 1 || payloadLength > c.cfg.maxPayload || payloadLength > len(plaintext)-innerHeaderSize {
		return nil, fmt.Errorf("%w: invalid payload length %d", ErrInvalidFrame, payloadLength)
	}
	paddingLength := len(plaintext) - innerHeaderSize - payloadLength
	if paddingLength > c.cfg.maxPadding {
		return nil, fmt.Errorf("%w: record padding too large", ErrInvalidFrame)
	}
	return plaintext[innerHeaderSize : innerHeaderSize+payloadLength], nil
}

func (c *Conn) drainPending(destination []byte) int {
	n := copy(destination, c.pending[c.pendingOffset:])
	c.pendingOffset += n
	if c.pendingOffset == len(c.pending) {
		c.pending = nil
		c.pendingOffset = 0
	}
	return n
}

// CloseWrite half-closes the underlying connection when it supports half-close.
func (c *Conn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

// CloseRead half-closes the underlying connection when it supports half-close.
func (c *Conn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return c.Conn.Close()
}

func newSession(master [32]byte, salt [sessionSaltSize]byte) (sessionState, error) {
	var session sessionState
	trafficKey := deriveBytes(master[:], "traffic-key", salt[:], 32)
	block, err := aes.NewCipher(trafficKey)
	if err != nil {
		return session, fmt.Errorf("enigma: create AES cipher: %w", err)
	}
	session.aead, err = cipher.NewGCM(block)
	if err != nil {
		return session, fmt.Errorf("enigma: create GCM: %w", err)
	}
	rotorSeed := deriveBytes(master[:], "rotor-seed", salt[:], 32)
	session.rotors = newRotorSet(rotorSeed)
	copy(session.lengthKey[:], deriveBytes(master[:], "length-key", salt[:], 32))
	copy(session.noncePrefix[:], deriveBytes(master[:], "nonce-prefix", salt[:], len(session.noncePrefix)))
	return session, nil
}

func maskLength(length []byte, key [32]byte, sequence uint64) {
	var context [8]byte
	binary.BigEndian.PutUint64(context[:], sequence)
	mask := deriveBytes(key[:], "length-mask", context[:], 2)
	length[0] ^= mask[0]
	length[1] ^= mask[1]
}

func frameNonce(prefix [4]byte, sequence uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func frameAAD(sequence uint64, ciphertextLength uint16) []byte {
	const context = "enigma/etp/v1/frame"
	aad := make([]byte, len(context)+8+2)
	copy(aad, context)
	binary.BigEndian.PutUint64(aad[len(context):], sequence)
	binary.BigEndian.PutUint16(aad[len(context)+8:], ciphertextLength)
	return aad
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
