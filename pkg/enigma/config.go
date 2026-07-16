// Package enigma implements ETP/1, an Enigma-inspired traffic obfuscation
// layer for ordered, reliable network streams.
//
// The rotor transform is not cryptographic protection. ETP/1 authenticates and
// encrypts every record with AES-256-GCM before applying the rotor transform.
package enigma

import (
	"errors"
	"fmt"
	"net"
)

const (
	protocolVersion = 1
	sessionSaltSize = 16

	defaultMaxPayload = 16 * 1024
	hardMaxPayload    = 32 * 1024
	hardMaxPadding    = 8 * 1024
)

const (
	defaultCoverAlphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	defaultPaddingAlphabet = " \t\r\n!\"#$%&'()*+,./:;<=>?@[\\]^`{|}~"
)

var (
	// ErrAuthentication indicates that a record failed AEAD authentication.
	ErrAuthentication = errors.New("enigma: record authentication failed")
	// ErrInvalidFrame indicates an invalid or out-of-bounds record structure.
	ErrInvalidFrame = errors.New("enigma: invalid frame")
	// ErrUnexpectedCoverByte indicates a byte that belongs to neither the cover
	// alphabet nor the configured padding alphabet.
	ErrUnexpectedCoverByte = errors.New("enigma: unexpected cover byte")
)

// Config controls an ETP/1 connection. Key must contain at least 32 bytes of
// high-entropy pre-shared key material.
type Config struct {
	Key []byte

	// CoverAlphabet must contain exactly 64 unique printable ASCII bytes. The
	// default is the URL-safe base64 alphabet.
	CoverAlphabet string
	// PaddingAlphabet contains printable bytes that the cover decoder may
	// ignore. It must be disjoint from CoverAlphabet.
	PaddingAlphabet string

	// MinPadding and MaxPadding bound authenticated random bytes added inside
	// each encrypted record.
	MinPadding int
	MaxPadding int

	// MinCoverPadding and MaxCoverPadding bound ignorable printable bytes added
	// to each encoded salt or frame.
	MinCoverPadding int
	MaxCoverPadding int

	// MaxPayload is the largest plaintext payload in one record. Writes larger
	// than this value are split across records.
	MaxPayload int
}

type normalizedConfig struct {
	master          [32]byte
	coverAlphabet   string
	paddingAlphabet string
	minPadding      int
	maxPadding      int
	minCoverPadding int
	maxCoverPadding int
	maxPayload      int
}

// Validate checks the ETP/1 configuration without performing network I/O.
func (cfg Config) Validate() error {
	_, err := normalizeConfig(cfg)
	return err
}

// NewConn wraps conn with the ETP/1 record and obfuscation layers.
func NewConn(conn net.Conn, cfg Config) (*Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("enigma: nil connection")
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	cover, err := newCoverCodec(normalized.coverAlphabet, normalized.paddingAlphabet)
	if err != nil {
		return nil, err
	}
	return newConn(conn, normalized, cover), nil
}

func normalizeConfig(cfg Config) (normalizedConfig, error) {
	var out normalizedConfig
	if len(cfg.Key) < 32 {
		return out, fmt.Errorf("enigma: key must contain at least 32 bytes")
	}

	cover := cfg.CoverAlphabet
	if cover == "" {
		cover = defaultCoverAlphabet
	}
	padding := cfg.PaddingAlphabet
	if padding == "" {
		padding = defaultPaddingAlphabet
	}
	if _, err := newCoverCodec(cover, padding); err != nil {
		return out, err
	}

	maxPayload := cfg.MaxPayload
	if maxPayload == 0 {
		maxPayload = defaultMaxPayload
	}
	if maxPayload < 1 || maxPayload > hardMaxPayload {
		return out, fmt.Errorf("enigma: MaxPayload must be between 1 and %d", hardMaxPayload)
	}
	if err := validatePaddingRange("record padding", cfg.MinPadding, cfg.MaxPadding); err != nil {
		return out, err
	}
	if err := validatePaddingRange("cover padding", cfg.MinCoverPadding, cfg.MaxCoverPadding); err != nil {
		return out, err
	}
	if cfg.MaxCoverPadding > 0 && len(padding) == 0 {
		return out, fmt.Errorf("enigma: PaddingAlphabet is required when cover padding is enabled")
	}

	out.master = deriveMaster(cfg.Key)
	out.coverAlphabet = cover
	out.paddingAlphabet = padding
	out.minPadding = cfg.MinPadding
	out.maxPadding = cfg.MaxPadding
	out.minCoverPadding = cfg.MinCoverPadding
	out.maxCoverPadding = cfg.MaxCoverPadding
	out.maxPayload = maxPayload
	return out, nil
}

func validatePaddingRange(name string, minValue, maxValue int) error {
	if minValue < 0 || maxValue < 0 || minValue > maxValue || maxValue > hardMaxPadding {
		return fmt.Errorf("enigma: invalid %s range [%d,%d]", name, minValue, maxValue)
	}
	return nil
}
