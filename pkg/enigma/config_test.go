package enigma

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestNormalizeConfig(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	cfg, err := normalizeConfig(Config{Key: key})
	if err != nil {
		t.Fatalf("normalizeConfig: %v", err)
	}
	if cfg.maxPayload != defaultMaxPayload {
		t.Fatalf("maxPayload = %d, want %d", cfg.maxPayload, defaultMaxPayload)
	}
	if cfg.coverAlphabet != defaultCoverAlphabet {
		t.Fatalf("unexpected default cover alphabet")
	}
}

func TestConfigValidation(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x21}, 32)
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "short key", cfg: Config{Key: validKey[:31]}},
		{name: "short alphabet", cfg: Config{Key: validKey, CoverAlphabet: "abc"}},
		{name: "duplicate alphabet", cfg: Config{Key: validKey, CoverAlphabet: strings.Repeat("A", 64)}},
		{name: "overlapping padding", cfg: Config{Key: validKey, PaddingAlphabet: "A"}},
		{name: "negative padding", cfg: Config{Key: validKey, MinPadding: -1}},
		{name: "reversed padding", cfg: Config{Key: validKey, MinPadding: 2, MaxPadding: 1}},
		{name: "large payload", cfg: Config{Key: validKey, MaxPayload: hardMaxPayload + 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeConfig(test.cfg); err == nil {
				t.Fatalf("normalizeConfig(%+v) succeeded", test.cfg)
			}
		})
	}
}

func TestNewConnRejectsNil(t *testing.T) {
	if _, err := NewConn(nil, Config{Key: bytes.Repeat([]byte{1}, 32)}); err == nil {
		t.Fatal("NewConn(nil) succeeded")
	}
}

var _ net.Conn = (*Conn)(nil)
