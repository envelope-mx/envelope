// Package ratelimit implements the token-bucket primitive behind
// per-source-IP and per-envelope-sender rate limiting (TRD FR-2.3).
//
// TokenBucket is in-process, unshared state: Phase 4 wires the same
// allow/deny contract to Goose's cache/kv module (keyed per IP/sender) so
// limits hold across replicas; this package only provides the bucket math.
package ratelimit

import (
	"sync"
	"time"
)

// TokenBucket is a thread-safe token-bucket limiter: capacity tokens max,
// refilled continuously at refillPerSecond tokens/second.
type TokenBucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	last       time.Time
	now        func() time.Time
}

// NewTokenBucket returns a TokenBucket starting full, with capacity tokens
// and a refill rate of refillPerSecond tokens/second.
func NewTokenBucket(capacity, refillPerSecond float64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillPerSecond,
		last:       time.Now(),
		now:        time.Now,
	}
}

// Allow reports whether a token is currently available and, if so,
// consumes it. Exceeding the limit yields false (FR-2.3: a temporary
// reject, not permanent — the caller decides the SMTP response code).
func (b *TokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill()
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// refill adds tokens for elapsed time since the last refill, capped at
// capacity. Must be called with mu held.
func (b *TokenBucket) refill() {
	now := b.now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.last = now

	b.tokens += elapsed * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}
