package enigma

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

type protocolVector struct {
	Protocol        string `json:"protocol"`
	PSKHex          string `json:"psk_hex"`
	SessionSaltHex  string `json:"session_salt_hex"`
	SequenceHex     string `json:"sequence_hex"`
	MasterHex       string `json:"master_hex"`
	TrafficKeyHex   string `json:"traffic_key_hex"`
	RotorSeedHex    string `json:"rotor_seed_hex"`
	LengthKeyHex    string `json:"length_key_hex"`
	NoncePrefixHex  string `json:"nonce_prefix_hex"`
	RotorStateHex   string `json:"rotor_state_hex"`
	RotorInputHex   string `json:"rotor_input_hex"`
	RotorOutputHex  string `json:"rotor_output_hex"`
	LengthHex       string `json:"length_hex"`
	MaskedLengthHex string `json:"masked_length_hex"`
	NonceHex        string `json:"nonce_hex"`
	AADHex          string `json:"aad_hex"`
}

func TestETP1ProtocolVector(t *testing.T) {
	encoded, err := os.ReadFile("testdata/etp1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector protocolVector
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Protocol != "ETP/1" {
		t.Fatalf("protocol = %q", vector.Protocol)
	}

	psk := mustDecodeHex(t, vector.PSKHex)
	saltBytes := mustDecodeHex(t, vector.SessionSaltHex)
	if len(saltBytes) != sessionSaltSize {
		t.Fatalf("session salt length = %d", len(saltBytes))
	}
	var salt [sessionSaltSize]byte
	copy(salt[:], saltBytes)
	sequence, err := strconv.ParseUint(vector.SequenceHex, 16, 64)
	if err != nil {
		t.Fatal(err)
	}

	master := deriveMaster(psk)
	assertHex(t, "master", master[:], vector.MasterHex)
	trafficKey := deriveBytes(master[:], "traffic-key", salt[:], 32)
	assertHex(t, "traffic key", trafficKey, vector.TrafficKeyHex)
	rotorSeed := deriveBytes(master[:], "rotor-seed", salt[:], 32)
	assertHex(t, "rotor seed", rotorSeed, vector.RotorSeedHex)

	session, err := newSession(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "length key", session.lengthKey[:], vector.LengthKeyHex)
	assertHex(t, "nonce prefix", session.noncePrefix[:], vector.NoncePrefixHex)

	var sequenceBytes [8]byte
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	state := deriveBytes(session.rotors.stateKey[:], "frame-rotor-state", sequenceBytes[:], rotorCount*2)
	assertHex(t, "rotor state", state, vector.RotorStateHex)

	rotorOutput := mustDecodeHex(t, vector.RotorInputHex)
	machine := session.rotors.machineFor(sequence)
	machine.transform(rotorOutput)
	assertHex(t, "rotor output", rotorOutput, vector.RotorOutputHex)

	maskedLength := mustDecodeHex(t, vector.LengthHex)
	if len(maskedLength) != 2 {
		t.Fatalf("length vector has %d bytes", len(maskedLength))
	}
	maskLength(maskedLength, session.lengthKey, sequence)
	assertHex(t, "masked length", maskedLength, vector.MaskedLengthHex)

	nonce := frameNonce(session.noncePrefix, sequence)
	assertHex(t, "nonce", nonce[:], vector.NonceHex)
	length := binary.BigEndian.Uint16(mustDecodeHex(t, vector.LengthHex))
	assertHex(t, "AAD", frameAAD(sequence, length), vector.AADHex)
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertHex(t *testing.T, name string, actual []byte, expected string) {
	t.Helper()
	if got := hex.EncodeToString(actual); got != expected {
		t.Fatalf("%s = %s, want %s", name, got, expected)
	}
}
