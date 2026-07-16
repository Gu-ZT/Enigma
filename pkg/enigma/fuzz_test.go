package enigma

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzRotorInvolution(f *testing.F) {
	f.Add([]byte("rotor seed"), uint64(0), []byte("hello ETP/1"))
	f.Add(bytes.Repeat([]byte{0xff}, 32), uint64(1), []byte{0x00, 0x7f, 0x80, 0xff})
	f.Fuzz(func(t *testing.T, seed []byte, sequence uint64, input []byte) {
		if len(seed) > 1024 || len(input) > 64*1024 {
			t.Skip()
		}
		set := newRotorSet(seed)
		transformed := append([]byte(nil), input...)
		forward := set.machineFor(sequence)
		forward.transform(transformed)
		reverse := set.machineFor(sequence)
		reverse.transform(transformed)
		if !bytes.Equal(transformed, input) {
			t.Fatal("rotor transform is not involutive")
		}
	})
}

func FuzzCoverRoundTrip(f *testing.F) {
	f.Add([]byte("hello ETP/1"), uint16(0))
	f.Add([]byte{0x00, 0x7f, 0x80, 0xff}, uint16(31))
	f.Fuzz(func(t *testing.T, input []byte, requestedPadding uint16) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		padding := int(requestedPadding % 257)
		encoder, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encoder.encode(input, padding, padding)
		if err != nil {
			t.Fatal(err)
		}
		decoder, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
		if err != nil {
			t.Fatal(err)
		}
		decoded := make([]byte, len(input))
		if _, err := decoder.readFull(bufio.NewReader(bytes.NewReader(encoded)), decoded); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded, input) {
			t.Fatal("cover round trip mismatch")
		}
	})
}

func FuzzCoverDecoder(f *testing.F) {
	f.Add([]byte("QUJDREVGRw=="))
	f.Add([]byte{0x00})
	f.Add([]byte("A"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 64*1024 {
			t.Skip()
		}
		decoder, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(bytes.NewReader(wire))
		for decoded := 0; decoded <= len(wire)/2; decoded++ {
			if _, err := decoder.readByte(reader); err != nil {
				return
			}
		}
		t.Fatal("decoder produced more bytes than the wire can contain")
	})
}

func FuzzConnReadFrame(f *testing.F) {
	f.Add([]byte("not an ETP stream"))
	f.Add(bytes.Repeat([]byte("A"), sessionSaltSize*2))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 64*1024 {
			t.Skip()
		}
		cfg := Config{
			Key:        bytes.Repeat([]byte{0x5a}, 32),
			MaxPayload: 1024,
			MaxPadding: 256,
		}
		conn, err := NewConn(newMemoryConn(wire), cfg)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, cfg.MaxPayload)
		_, _ = conn.Read(buffer)
	})
}

func FuzzLengthMaskRoundTrip(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(0), uint16(20))
	f.Fuzz(func(t *testing.T, keyBytes []byte, sequence uint64, length uint16) {
		if len(keyBytes) > 1024 {
			t.Skip()
		}
		var key [32]byte
		copy(key[:], keyBytes)
		var value [2]byte
		binary.BigEndian.PutUint16(value[:], length)
		maskLength(value[:], key, sequence)
		maskLength(value[:], key, sequence)
		if got := binary.BigEndian.Uint16(value[:]); got != length {
			t.Fatalf("length mask round trip = %d, want %d", got, length)
		}
	})
}
