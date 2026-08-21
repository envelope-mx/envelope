package queue_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/isaiahiroko/envelope/internal/queue"
)

func TestFullJitterWithinBounds(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	base := 100 * time.Millisecond
	maxDelay := 10 * time.Second

	for attempt := 0; attempt < 20; attempt++ {
		for i := 0; i < 100; i++ {
			d := queue.FullJitter(attempt, base, maxDelay, r)
			if d < 0 || d >= maxDelay {
				t.Fatalf("attempt %d: delay %v out of [0, %v)", attempt, d, maxDelay)
			}
		}
	}
}

func TestFullJitterGrowsWithAttempt(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	base := 1 * time.Millisecond
	maxDelay := time.Hour

	// The theoretical upper bound (base*2^attempt) must grow with attempt
	// up to the cap; sample many draws per attempt and compare maxima as a
	// proxy, since individual draws are randomized across the full range.
	maxAt := func(attempt int) time.Duration {
		var max time.Duration
		for i := 0; i < 500; i++ {
			if d := queue.FullJitter(attempt, base, maxDelay, r); d > max {
				max = d
			}
		}
		return max
	}

	if maxAt(0) >= maxAt(5) {
		t.Fatalf("expected attempt 5's sampled max to exceed attempt 0's")
	}
}

func TestFullJitterClampsAtCap(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	base := 1 * time.Second
	maxDelay := 2 * time.Second

	for i := 0; i < 100; i++ {
		// A high attempt count would overflow without clamping.
		d := queue.FullJitter(50, base, maxDelay, r)
		if d < 0 || d >= maxDelay {
			t.Fatalf("delay %v out of [0, %v) at high attempt count", d, maxDelay)
		}
	}
}

func TestFullJitterZeroCap(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	if d := queue.FullJitter(0, time.Second, 0, r); d != 0 {
		t.Fatalf("expected 0 delay for zero cap, got %v", d)
	}
}

func TestFullJitterDeterministicWithSeededRand(t *testing.T) {
	base := 100 * time.Millisecond
	maxDelay := 10 * time.Second

	r1 := rand.New(rand.NewSource(42))
	r2 := rand.New(rand.NewSource(42))

	for attempt := 0; attempt < 10; attempt++ {
		d1 := queue.FullJitter(attempt, base, maxDelay, r1)
		d2 := queue.FullJitter(attempt, base, maxDelay, r2)
		if d1 != d2 {
			t.Fatalf("attempt %d: same seed produced different results: %v vs %v", attempt, d1, d2)
		}
	}
}
