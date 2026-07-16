package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"Enigma/pkg/enigma"
)

const (
	handshakeVersion = 1
	clientHelloType  = 1
	serverHelloType  = 2

	handshakeNonceSize = 12
	clientNonceSize    = 16
	serverNonceSize    = 16
	publicKeySize      = 32

	clientPlaintextSize = 1 + 1 + 8 + clientNonceSize + publicKeySize
	serverPlaintextSize = 1 + 1 + clientNonceSize + serverNonceSize + publicKeySize
	handshakeTagSize    = 16
	clientPacketSize    = handshakeNonceSize + clientPlaintextSize + handshakeTagSize
	serverPacketSize    = handshakeNonceSize + serverPlaintextSize + handshakeTagSize
)

const handshakePrefix = "enigma/etph/v1/"

var (
	// ErrAuthentication indicates that a handshake packet could not be authenticated.
	ErrAuthentication = errors.New("tunnel: handshake authentication failed")
	// ErrProtocol indicates a malformed or unexpected handshake message.
	ErrProtocol = errors.New("tunnel: invalid handshake message")
	// ErrReplay indicates reuse of an authenticated client nonce.
	ErrReplay = errors.New("tunnel: replayed client hello")
	// ErrReplayCacheFull indicates that strict replay tracking has reached its
	// configured capacity and cannot safely accept another live nonce.
	ErrReplayCacheFull = errors.New("tunnel: replay cache full")
	// ErrClockSkew indicates a client timestamp outside the accepted window.
	ErrClockSkew = errors.New("tunnel: client clock outside accepted window")
)

type clientHandshakeState struct {
	private *ecdh.PrivateKey
	public  [publicKeySize]byte
	nonce   [clientNonceSize]byte
	packet  [clientPacketSize]byte
}

type acceptedClientHello struct {
	public [publicKeySize]byte
	nonce  [clientNonceSize]byte
}

// NewClientConn performs an ETPH/1 client handshake and wraps raw with ETP/1
// using the derived forward-secret session key.
func NewClientConn(raw net.Conn, cfg Config) (*enigma.Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("tunnel: nil connection")
	}
	normalized, err := normalizeConfig(cfg, false)
	if err != nil {
		return nil, err
	}
	if err := setHandshakeDeadline(raw, normalized); err != nil {
		return nil, err
	}
	sessionKey, err := clientHandshake(raw, normalized)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("tunnel: clear handshake deadline: %w", err)
	}
	normalized.codec.Key = sessionKey
	return enigma.NewConn(raw, normalized.codec)
}

// NewServerConn performs an ETPH/1 server handshake and wraps raw with ETP/1
// using the derived forward-secret session key.
func NewServerConn(raw net.Conn, cfg Config) (*enigma.Conn, error) {
	if raw == nil {
		return nil, fmt.Errorf("tunnel: nil connection")
	}
	normalized, err := normalizeConfig(cfg, true)
	if err != nil {
		return nil, err
	}
	if err := setHandshakeDeadline(raw, normalized); err != nil {
		return nil, err
	}
	sessionKey, err := serverHandshake(raw, normalized)
	if err != nil {
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("tunnel: clear handshake deadline: %w", err)
	}
	normalized.codec.Key = sessionKey
	return enigma.NewConn(raw, normalized.codec)
}

func setHandshakeDeadline(raw net.Conn, cfg normalizedConfig) error {
	if cfg.timeout == 0 {
		return nil
	}
	if err := raw.SetDeadline(cfg.now().Add(cfg.timeout)); err != nil {
		return fmt.Errorf("tunnel: set handshake deadline: %w", err)
	}
	return nil
}

func clientHandshake(raw net.Conn, cfg normalizedConfig) ([]byte, error) {
	state, err := buildClientHello(cfg.psk, cfg.now())
	if err != nil {
		return nil, err
	}
	if err := writeFull(raw, state.packet[:]); err != nil {
		return nil, fmt.Errorf("tunnel: write client hello: %w", err)
	}
	var response [serverPacketSize]byte
	if _, err := io.ReadFull(raw, response[:]); err != nil {
		return nil, fmt.Errorf("tunnel: read server hello: %w", err)
	}
	plaintext, err := openHandshakePacket(cfg.psk, serverAAD(state.packet[:]), response[:])
	if err != nil {
		return nil, err
	}
	if len(plaintext) != serverPlaintextSize || plaintext[0] != handshakeVersion || plaintext[1] != serverHelloType {
		return nil, ErrProtocol
	}
	if !hmac.Equal(plaintext[2:2+clientNonceSize], state.nonce[:]) {
		return nil, fmt.Errorf("%w: client nonce mismatch", ErrProtocol)
	}
	var serverNonce [serverNonceSize]byte
	copy(serverNonce[:], plaintext[2+clientNonceSize:2+clientNonceSize+serverNonceSize])
	var serverPublic [publicKeySize]byte
	copy(serverPublic[:], plaintext[2+clientNonceSize+serverNonceSize:])
	shared, err := sharedSecret(state.private, serverPublic)
	if err != nil {
		return nil, err
	}
	return deriveSessionKey(cfg.psk, shared, state.nonce, serverNonce, state.public, serverPublic), nil
}

func serverHandshake(raw net.Conn, cfg normalizedConfig) ([]byte, error) {
	var packet [clientPacketSize]byte
	if _, err := io.ReadFull(raw, packet[:]); err != nil {
		return nil, fmt.Errorf("tunnel: read client hello: %w", err)
	}
	hello, err := acceptClientHello(cfg.psk, packet, cfg.now(), cfg.maxClockSkew, cfg.replayGuard)
	if err != nil {
		return nil, err
	}
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tunnel: generate server key: %w", err)
	}
	var serverPublic [publicKeySize]byte
	copy(serverPublic[:], private.PublicKey().Bytes())
	var serverNonce [serverNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return nil, fmt.Errorf("tunnel: generate server nonce: %w", err)
	}

	plaintext := make([]byte, serverPlaintextSize)
	plaintext[0] = handshakeVersion
	plaintext[1] = serverHelloType
	copy(plaintext[2:], hello.nonce[:])
	copy(plaintext[2+clientNonceSize:], serverNonce[:])
	copy(plaintext[2+clientNonceSize+serverNonceSize:], serverPublic[:])
	response, err := sealHandshakePacket(cfg.psk, serverAAD(packet[:]), plaintext)
	if err != nil {
		return nil, err
	}
	shared, err := sharedSecret(private, hello.public)
	if err != nil {
		return nil, err
	}
	if err := writeFull(raw, response); err != nil {
		return nil, fmt.Errorf("tunnel: write server hello: %w", err)
	}
	return deriveSessionKey(cfg.psk, shared, hello.nonce, serverNonce, hello.public, serverPublic), nil
}

func buildClientHello(psk []byte, now time.Time) (clientHandshakeState, error) {
	var state clientHandshakeState
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return state, fmt.Errorf("tunnel: generate client key: %w", err)
	}
	state.private = private
	copy(state.public[:], private.PublicKey().Bytes())
	if _, err := io.ReadFull(rand.Reader, state.nonce[:]); err != nil {
		return state, fmt.Errorf("tunnel: generate client nonce: %w", err)
	}
	plaintext := make([]byte, clientPlaintextSize)
	plaintext[0] = handshakeVersion
	plaintext[1] = clientHelloType
	binary.BigEndian.PutUint64(plaintext[2:10], uint64(now.Unix()))
	copy(plaintext[10:10+clientNonceSize], state.nonce[:])
	copy(plaintext[10+clientNonceSize:], state.public[:])
	packet, err := sealHandshakePacket(psk, clientAAD(), plaintext)
	if err != nil {
		return state, err
	}
	copy(state.packet[:], packet)
	return state, nil
}

func acceptClientHello(psk []byte, packet [clientPacketSize]byte, now time.Time, maxClockSkew time.Duration, guard *ReplayGuard) (acceptedClientHello, error) {
	var hello acceptedClientHello
	plaintext, err := openHandshakePacket(psk, clientAAD(), packet[:])
	if err != nil {
		return hello, err
	}
	if len(plaintext) != clientPlaintextSize || plaintext[0] != handshakeVersion || plaintext[1] != clientHelloType {
		return hello, ErrProtocol
	}
	timestamp := int64(binary.BigEndian.Uint64(plaintext[2:10]))
	clientTime := time.Unix(timestamp, 0)
	if clientTime.Before(now.Add(-maxClockSkew)) || clientTime.After(now.Add(maxClockSkew)) {
		return hello, ErrClockSkew
	}
	copy(hello.nonce[:], plaintext[10:10+clientNonceSize])
	copy(hello.public[:], plaintext[10+clientNonceSize:])
	if guard == nil {
		return hello, fmt.Errorf("%w: missing replay guard", ErrProtocol)
	}
	if err := guard.accept(hello.nonce, now); err != nil {
		return hello, err
	}
	return hello, nil
}

func sealHandshakePacket(psk, aad, plaintext []byte) ([]byte, error) {
	aead, err := handshakeAEAD(psk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, handshakeNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("tunnel: generate handshake nonce: %w", err)
	}
	packet := make([]byte, handshakeNonceSize, handshakeNonceSize+len(plaintext)+aead.Overhead())
	copy(packet, nonce)
	packet = aead.Seal(packet, nonce, plaintext, aad)
	return packet, nil
}

func openHandshakePacket(psk, aad, packet []byte) ([]byte, error) {
	if len(packet) < handshakeNonceSize+handshakeTagSize {
		return nil, ErrProtocol
	}
	aead, err := handshakeAEAD(psk)
	if err != nil {
		return nil, err
	}
	nonce := packet[:handshakeNonceSize]
	plaintext, err := aead.Open(nil, nonce, packet[handshakeNonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	return plaintext, nil
}

func handshakeAEAD(psk []byte) (cipher.AEAD, error) {
	key := hmacValue(psk, []byte(handshakePrefix+"handshake-key"))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create handshake cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create handshake GCM: %w", err)
	}
	return aead, nil
}

func deriveSessionKey(psk, shared []byte, clientNonce [clientNonceSize]byte, serverNonce [serverNonceSize]byte, clientPublic, serverPublic [publicKeySize]byte) []byte {
	extractInput := make([]byte, 0, len(handshakePrefix)+len(clientNonce)+len(serverNonce))
	extractInput = append(extractInput, handshakePrefix+"extract"...)
	extractInput = append(extractInput, clientNonce[:]...)
	extractInput = append(extractInput, serverNonce[:]...)
	extractSalt := hmacValue(psk, extractInput)
	prk := hmacValue(extractSalt, shared)
	context := make([]byte, 0, len(handshakePrefix)+len(clientPublic)+len(serverPublic))
	context = append(context, handshakePrefix+"session-key"...)
	context = append(context, clientPublic[:]...)
	context = append(context, serverPublic[:]...)
	return hmacValue(prk, context)
}

func sharedSecret(private *ecdh.PrivateKey, peerPublic [publicKeySize]byte) ([]byte, error) {
	public, err := ecdh.X25519().NewPublicKey(peerPublic[:])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid X25519 public key", ErrProtocol)
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, fmt.Errorf("%w: X25519 exchange failed", ErrProtocol)
	}
	return shared, nil
}

func hmacValue(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func clientAAD() []byte {
	return []byte(handshakePrefix + "client")
}

func serverAAD(clientPacket []byte) []byte {
	digest := sha256.Sum256(clientPacket)
	aad := make([]byte, 0, len(handshakePrefix)+len("server")+len(digest))
	aad = append(aad, handshakePrefix+"server"...)
	aad = append(aad, digest[:]...)
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
