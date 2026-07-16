package enigma

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

func BenchmarkRotorTransform32K(b *testing.B) {
	set := newRotorSet(bytes.Repeat([]byte{0x31}, 32))
	original := makePattern(32*1024, 7)
	buffer := make([]byte, len(original))
	b.SetBytes(int64(len(original)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buffer, original)
		machine := set.machineFor(uint64(i))
		machine.transform(buffer)
	}
}

func BenchmarkCoverEncode32K(b *testing.B) {
	codec, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
	if err != nil {
		b.Fatal(err)
	}
	payload := makePattern(32*1024, 11)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := codec.encode(payload, 0, 64); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCoverDecode32K(b *testing.B) {
	codec, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
	if err != nil {
		b.Fatal(err)
	}
	payload := makePattern(32*1024, 13)
	wire, err := codec.encode(payload, 64, 64)
	if err != nil {
		b.Fatal(err)
	}
	decoded := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decoder, err := newCoverCodec(defaultCoverAlphabet, defaultPaddingAlphabet)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := decoder.readFull(bufio.NewReader(bytes.NewReader(wire)), decoded); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnRoundTrip32K(b *testing.B) {
	cfg := Config{
		Key:             bytes.Repeat([]byte{0x72}, 32),
		MinPadding:      8,
		MaxPadding:      64,
		MinCoverPadding: 8,
		MaxCoverPadding: 64,
	}
	payload := makePattern(32*1024, 17)
	decoded := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		transport := newMemoryConn(nil)
		writer, err := NewConn(transport, cfg)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := writer.Write(payload); err != nil {
			b.Fatal(err)
		}
		reader, err := NewConn(newMemoryConn(transport.BytesCopy()), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(reader, decoded); err != nil {
			b.Fatal(err)
		}
	}
}
