package queue

import (
	"math"
	"math/rand"
	"time"
)

// FullJitter computes a retry delay using the "full jitter" algorithm: a
// duration chosen uniformly from [0, min(cap, base*2^attempt)) (TRD FR-3.4,
// bounded by backoff_max_secs). attempt is 0-indexed: 0 is the delay before
// the first retry. r is explicit rather than a package-level default so
// callers get deterministic, testable output.
func FullJitter(attempt int, base, maxDelay time.Duration, r *rand.Rand) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	upper := float64(base) * math.Pow(2, float64(attempt))
	if upper > float64(maxDelay) || math.IsInf(upper, 1) {
		upper = float64(maxDelay)
	}
	if upper <= 0 {
		return 0
	}

	return time.Duration(r.Int63n(int64(upper)))
}
