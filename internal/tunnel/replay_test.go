package tunnel

import (
	"sync"
	"testing"
	"time"
)

func TestReplayGuardRejectsDuplicateUntilExpiry(t *testing.T) {
	guard, err := NewReplayGuard(4, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	var nonce [clientNonceSize]byte
	nonce[0] = 1
	if err := guard.accept(nonce, now); err != nil {
		t.Fatal("first nonce rejected")
	}
	if err := guard.accept(nonce, now.Add(time.Second)); err != ErrReplay {
		t.Fatalf("duplicate nonce error = %v", err)
	}
	if err := guard.accept(nonce, now.Add(time.Minute)); err != nil {
		t.Fatal("expired nonce rejected")
	}
}

func TestReplayGuardRejectsNewNonceAtCapacity(t *testing.T) {
	guard, err := NewReplayGuard(2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000, 0)
	for i := byte(0); i < 2; i++ {
		var nonce [clientNonceSize]byte
		nonce[0] = i
		if err := guard.accept(nonce, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("nonce %d rejected", i)
		}
	}
	var extra [clientNonceSize]byte
	extra[0] = 2
	if err := guard.accept(extra, now.Add(2*time.Second)); err != ErrReplayCacheFull {
		t.Fatalf("full cache error = %v", err)
	}
	if len(guard.seen) != guard.maxEntries {
		t.Fatalf("cache grew to %d entries", len(guard.seen))
	}
	if err := guard.accept(extra, now.Add(time.Hour)); err != nil {
		t.Fatalf("nonce rejected after expiry: %v", err)
	}
}

func TestReplayGuardConcurrentUse(t *testing.T) {
	guard, err := NewReplayGuard(128, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(3000, 0)
	var wait sync.WaitGroup
	for i := 0; i < 64; i++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			var nonce [clientNonceSize]byte
			nonce[0] = value
			_ = guard.accept(nonce, now)
		}(byte(i))
	}
	wait.Wait()
	if len(guard.seen) != 64 {
		t.Fatalf("cache entries = %d, want 64", len(guard.seen))
	}
}

func TestNewReplayGuardValidation(t *testing.T) {
	if _, err := NewReplayGuard(0, time.Minute); err == nil {
		t.Fatal("zero capacity accepted")
	}
	if _, err := NewReplayGuard(1, 0); err == nil {
		t.Fatal("zero TTL accepted")
	}
}
