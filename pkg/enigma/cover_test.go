package enigma

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestCoverRoundTripWithPadding(t *testing.T) {
	encoder, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
	if err != nil {
		t.Fatalf("newCoverCodec: %v", err)
	}
	raw := make([]byte, 1024)
	for i := range raw {
		raw[i] = byte(i)
	}
	encoded, err := encoder.encode(raw, 257, 257)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) != len(raw)*2+257 {
		t.Fatalf("encoded length = %d", len(encoded))
	}

	decoder, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
	if err != nil {
		t.Fatalf("newCoverCodec decoder: %v", err)
	}
	decoded := make([]byte, len(raw))
	if _, err := decoder.readFull(bufio.NewReaderSize(bytes.NewReader(encoded), 7), decoded); err != nil {
		t.Fatalf("readFull: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatal("cover round trip mismatch")
	}
}

func TestCoverUsesWireVariants(t *testing.T) {
	codec, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		encoded, err := codec.encode([]byte{0xab}, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(encoded)] = true
	}
	if len(seen) < 2 {
		t.Fatal("cover encoding did not produce alternate representations")
	}
}

func TestCoverRejectsUnexpectedAndTruncatedInput(t *testing.T) {
	codec, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.readByte(bufio.NewReader(bytes.NewReader([]byte{0x00}))); !errors.Is(err, ErrUnexpectedCoverByte) {
		t.Fatalf("unexpected byte error = %v", err)
	}

	codec, err = newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.readByte(bufio.NewReader(bytes.NewReader([]byte{'A'}))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated symbol error = %v", err)
	}
}
