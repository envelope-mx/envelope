package ratelimit

import (
	"testing"
	"time"
)

// fakeClock lets tests advance time deterministically instead of sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestBucket(capacity, refillPerSecond float64) (*TokenBucket, *fakeClock) {
	clock := &fakeClock{t: time.Now()}
	b := NewTokenBucket(capacity, refillPerSecond)
	b.last = clock.t
	b.now = clock.now
	return b, clock
}

func TestAllowConsumesCapacityThenDenies(t *testing.T) {
	b, _ := newTestBucket(3, 0)

	for i := 0; i < 3; i++ {
		if !b.Allow() {
			t.Fatalf("expected Allow() to succeed on request %d", i+1)
		}
	}
	if b.Allow() {
		t.Fatal("expected Allow() to fail once capacity is exhausted")
	}
}

func TestRefillReplenishesOverTime(t *testing.T) {
	b, clock := newTestBucket(2, 1) // 1 token/sec

	if !b.Allow() || !b.Allow() {
		t.Fatal("expected both initial tokens to be available")
	}
	if b.Allow() {
		t.Fatal("expected bucket to be empty")
	}

	clock.advance(1500 * time.Millisecond) // refills 1.5 tokens
	if !b.Allow() {
		t.Fatal("expected a token to be available after refill")
	}
	if b.Allow() {
		t.Fatal("expected only one token to have refilled (1.5 - 1 < 1)")
	}
}

func TestRefillCapsAtCapacity(t *testing.T) {
	b, clock := newTestBucket(2, 1)

	// Drain, then wait far longer than needed to refill to capacity.
	b.Allow()
	b.Allow()
	clock.advance(time.Hour)

	if !b.Allow() || !b.Allow() {
		t.Fatal("expected bucket to have refilled to at least capacity")
	}
	if b.Allow() {
		t.Fatal("expected refill to cap at capacity, not accumulate unbounded")
	}
}
