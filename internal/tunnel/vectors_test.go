package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type handshakeVector struct {
	Protocol            string `json:"protocol"`
	Timestamp           int64  `json:"timestamp"`
	PSKHex              string `json:"psk_hex"`
	HandshakeKeyHex     string `json:"handshake_key_hex"`
	ClientPrivateHex    string `json:"client_private_hex"`
	ClientPublicHex     string `json:"client_public_hex"`
	ServerPrivateHex    string `json:"server_private_hex"`
	ServerPublicHex     string `json:"server_public_hex"`
	ClientNonceHex      string `json:"client_nonce_hex"`
	ServerNonceHex      string `json:"server_nonce_hex"`
	ClientOuterNonceHex string `json:"client_outer_nonce_hex"`
	ServerOuterNonceHex string `json:"server_outer_nonce_hex"`
	ClientPlaintextHex  string `json:"client_plaintext_hex"`
	ClientPacketHex     string `json:"client_packet_hex"`
	ServerPlaintextHex  string `json:"server_plaintext_hex"`
	ServerPacketHex     string `json:"server_packet_hex"`
	SharedSecretHex     string `json:"shared_secret_hex"`
	ExtractSaltHex      string `json:"extract_salt_hex"`
	PRKHex              string `json:"prk_hex"`
	SessionKeyHex       string `json:"session_key_hex"`
}

func TestETPH1ProtocolVector(t *testing.T) {
	encoded, err := os.ReadFile("testdata/etph1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector handshakeVector
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Protocol != "ETPH/1" {
		t.Fatalf("protocol = %q", vector.Protocol)
	}

	psk := decodeHex(t, vector.PSKHex)
	assertBytes(t, "handshake key", hmacValue(psk, []byte(handshakePrefix+"handshake-key")), vector.HandshakeKeyHex)
	clientPrivate, err := ecdh.X25519().NewPrivateKey(decodeHex(t, vector.ClientPrivateHex))
	if err != nil {
		t.Fatal(err)
	}
	serverPrivate, err := ecdh.X25519().NewPrivateKey(decodeHex(t, vector.ServerPrivateHex))
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, "client public", clientPrivate.PublicKey().Bytes(), vector.ClientPublicHex)
	assertBytes(t, "server public", serverPrivate.PublicKey().Bytes(), vector.ServerPublicHex)

	var clientNonce [clientNonceSize]byte
	var serverNonce [serverNonceSize]byte
	var clientPublic [publicKeySize]byte
	var serverPublic [publicKeySize]byte
	copy(clientNonce[:], decodeHex(t, vector.ClientNonceHex))
	copy(serverNonce[:], decodeHex(t, vector.ServerNonceHex))
	copy(clientPublic[:], clientPrivate.PublicKey().Bytes())
	copy(serverPublic[:], serverPrivate.PublicKey().Bytes())

	clientPlaintext := make([]byte, clientPlaintextSize)
	clientPlaintext[0] = handshakeVersion
	clientPlaintext[1] = clientHelloType
	binary.BigEndian.PutUint64(clientPlaintext[2:10], uint64(vector.Timestamp))
	copy(clientPlaintext[10:], clientNonce[:])
	copy(clientPlaintext[10+clientNonceSize:], clientPublic[:])
	assertBytes(t, "client plaintext", clientPlaintext, vector.ClientPlaintextHex)

	aead, err := handshakeAEAD(psk)
	if err != nil {
		t.Fatal(err)
	}
	clientOuterNonce := decodeHex(t, vector.ClientOuterNonceHex)
	clientPacket := append([]byte(nil), clientOuterNonce...)
	clientPacket = aead.Seal(clientPacket, clientOuterNonce, clientPlaintext, clientAAD())
	assertBytes(t, "client packet", clientPacket, vector.ClientPacketHex)

	serverPlaintext := make([]byte, serverPlaintextSize)
	serverPlaintext[0] = handshakeVersion
	serverPlaintext[1] = serverHelloType
	copy(serverPlaintext[2:], clientNonce[:])
	copy(serverPlaintext[2+clientNonceSize:], serverNonce[:])
	copy(serverPlaintext[2+clientNonceSize+serverNonceSize:], serverPublic[:])
	assertBytes(t, "server plaintext", serverPlaintext, vector.ServerPlaintextHex)
	serverOuterNonce := decodeHex(t, vector.ServerOuterNonceHex)
	serverPacket := append([]byte(nil), serverOuterNonce...)
	serverPacket = aead.Seal(serverPacket, serverOuterNonce, serverPlaintext, serverAAD(clientPacket))
	assertBytes(t, "server packet", serverPacket, vector.ServerPacketHex)

	shared, err := clientPrivate.ECDH(serverPrivate.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	serverShared, err := serverPrivate.ECDH(clientPrivate.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, serverShared) {
		t.Fatal("X25519 shared secrets differ")
	}
	assertBytes(t, "shared secret", shared, vector.SharedSecretHex)
	extractInput := append([]byte(handshakePrefix+"extract"), clientNonce[:]...)
	extractInput = append(extractInput, serverNonce[:]...)
	extractSalt := hmacValue(psk, extractInput)
	assertBytes(t, "extract salt", extractSalt, vector.ExtractSaltHex)
	prk := hmacValue(extractSalt, shared)
	assertBytes(t, "PRK", prk, vector.PRKHex)
	sessionKey := deriveSessionKey(psk, shared, clientNonce, serverNonce, clientPublic, serverPublic)
	assertBytes(t, "session key", sessionKey, vector.SessionKeyHex)
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertBytes(t *testing.T, name string, actual []byte, expectedHex string) {
	t.Helper()
	if actualHex := hex.EncodeToString(actual); actualHex != expectedHex {
		t.Fatalf("%s = %s, want %s", name, actualHex, expectedHex)
	}
}
