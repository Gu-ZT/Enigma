package enigma_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"Enigma/pkg/enigma"
)

func TestPublicAPIInteroperabilityMatrix(t *testing.T) {
	tests := []struct {
		name   string
		config enigma.Config
	}{
		{
			name: "default",
			config: enigma.Config{
				Key: bytes.Repeat([]byte{0x11}, 32),
			},
		},
		{
			name: "balanced-padding-small-frames",
			config: enigma.Config{
				Key:             bytes.Repeat([]byte{0x42}, 32),
				MinPadding:      4,
				MaxPadding:      64,
				MinCoverPadding: 2,
				MaxCoverPadding: 32,
				MaxPayload:      257,
			},
		},
		{
			name: "custom-cover",
			config: enigma.Config{
				Key:             bytes.Repeat([]byte{0x7a}, 48),
				CoverAlphabet:   "_-9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA",
				PaddingAlphabet: " \t\r\n!#$%&()*+,./:;=?@[\\]^`{|}~\"'",
				MinPadding:      1,
				MaxPadding:      8,
				MinCoverPadding: 1,
				MaxCoverPadding: 8,
				MaxPayload:      1024,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runPublicInterop(t, test.config)
		})
	}
}

func runPublicInterop(t *testing.T, cfg enigma.Config) {
	t.Helper()
	rawLeft, rawRight := net.Pipe()
	defer rawLeft.Close()
	defer rawRight.Close()
	left, err := enigma.NewConn(rawLeft, cfg)
	if err != nil {
		t.Fatal(err)
	}
	right, err := enigma.NewConn(rawRight, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := left.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := right.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	toRight := bytes.Repeat([]byte{0x00, 0xff, 'E', 'T', 'P'}, 5000)
	toLeft := bytes.Repeat([]byte("public-api-interoperability"), 1000)
	leftReceived := make([]byte, len(toLeft))
	rightReceived := make([]byte, len(toRight))
	errCh := make(chan error, 4)
	go func() {
		_, err := left.Write(toRight)
		errCh <- err
	}()
	go func() {
		_, err := right.Write(toLeft)
		errCh <- err
	}()
	go func() {
		_, err := io.ReadFull(left, leftReceived)
		errCh <- err
	}()
	go func() {
		_, err := io.ReadFull(right, rightReceived)
		errCh <- err
	}()
	for i := 0; i < 4; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(leftReceived, toLeft) {
		t.Fatal("left payload mismatch")
	}
	if !bytes.Equal(rightReceived, toRight) {
		t.Fatal("right payload mismatch")
	}
}
