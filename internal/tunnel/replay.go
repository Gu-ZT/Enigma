package tunnel

import (
	"fmt"
	"sync"
	"time"
)

// ReplayGuard tracks authenticated client nonces for a bounded time window.
type ReplayGuard struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	seen       map[[clientNonceSize]byte]time.Time
}

// NewReplayGuard creates a bounded replay cache. maxEntries and ttl must be
// positive. New nonces are rejected while all entries are occupied and live.
func NewReplayGuard(maxEntries int, ttl time.Duration) (*ReplayGuard, error) {
	if maxEntries <= 0 {
		return nil, fmt.Errorf("tunnel: replay maxEntries must be positive")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("tunnel: replay TTL must be positive")
	}
	return &ReplayGuard{
		ttl:        ttl,
		maxEntries: maxEntries,
		seen:       make(map[[clientNonceSize]byte]time.Time),
	}, nil
}

func (g *ReplayGuard) accept(nonce [clientNonceSize]byte, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	for value, expires := range g.seen {
		if !now.Before(expires) {
			delete(g.seen, value)
		}
	}
	if expires, exists := g.seen[nonce]; exists && now.Before(expires) {
		return ErrReplay
	}
	if len(g.seen) >= g.maxEntries {
		return ErrReplayCacheFull
	}
	g.seen[nonce] = now.Add(g.ttl)
	return nil
}
