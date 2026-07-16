// Package tunnel authenticates peers, establishes forward-secret session key
// material, and upgrades a reliable stream to ETP/1.
package tunnel

import (
	"fmt"
	"time"

	"Enigma/pkg/enigma"
)

const (
	defaultHandshakeTimeout = 10 * time.Second
	defaultMaxClockSkew     = 60 * time.Second
	maxClockSkewLimit       = 10 * time.Minute
)

// Config controls the ETPH/1 handshake and the resulting ETP/1 connection.
// Codec.Key is the handshake PSK; it is replaced with the forward-secret
// session key before the ETP/1 connection is created.
type Config struct {
	Codec enigma.Config

	// HandshakeTimeout bounds all ETPH/1 reads and writes. Zero selects the
	// default of 10 seconds.
	HandshakeTimeout time.Duration
	// MaxClockSkew bounds accepted client timestamps. Zero selects 60 seconds.
	MaxClockSkew time.Duration
	// ReplayGuard is required by servers and must retain nonces for at least
	// twice MaxClockSkew.
	ReplayGuard *ReplayGuard

	now func() time.Time
}

type normalizedConfig struct {
	codec        enigma.Config
	psk          []byte
	timeout      time.Duration
	maxClockSkew time.Duration
	replayGuard  *ReplayGuard
	now          func() time.Time
}

func normalizeConfig(cfg Config, server bool) (normalizedConfig, error) {
	var out normalizedConfig
	if err := cfg.Codec.Validate(); err != nil {
		return out, fmt.Errorf("tunnel: invalid codec config: %w", err)
	}
	timeout := cfg.HandshakeTimeout
	if timeout == 0 {
		timeout = defaultHandshakeTimeout
	}
	if timeout < 0 {
		return out, fmt.Errorf("tunnel: HandshakeTimeout must not be negative")
	}
	maxClockSkew := cfg.MaxClockSkew
	if maxClockSkew == 0 {
		maxClockSkew = defaultMaxClockSkew
	}
	if maxClockSkew < 0 {
		return out, fmt.Errorf("tunnel: MaxClockSkew must not be negative")
	}
	if maxClockSkew > maxClockSkewLimit {
		return out, fmt.Errorf("tunnel: MaxClockSkew must not exceed %s", maxClockSkewLimit)
	}
	if server && cfg.ReplayGuard == nil {
		return out, fmt.Errorf("tunnel: server ReplayGuard is required")
	}
	if server && cfg.ReplayGuard.ttl < 2*maxClockSkew {
		return out, fmt.Errorf("tunnel: ReplayGuard TTL must be at least twice MaxClockSkew")
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	out.codec = cfg.Codec
	out.psk = append([]byte(nil), cfg.Codec.Key...)
	out.timeout = timeout
	out.maxClockSkew = maxClockSkew
	out.replayGuard = cfg.ReplayGuard
	out.now = now
	return out, nil
}
