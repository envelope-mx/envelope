// Package queue wraps Goose's queues module for durable outbound delivery
// (TRD FR-3.x).
package queue

import (
	"context"
	"time"
)

// Backend is the outbound-delivery queue contract. The queue must persist
// jobs durably before Enqueue returns (FR-3.3) — Phase 1 ships only an
// in-memory implementation (NewMemoryBackend) so Phase 2 can compile
// against the real contract; Phase 3 replaces it with one backed by
// Goose's queues module without changing this interface.
type Backend interface {
	// Enqueue durably persists job and makes it eligible for Dequeue once
	// its NextAttemptAt has passed.
	Enqueue(ctx context.Context, job Job) error

	// Dequeue claims and returns the next due job, if any. ok is false
	// when no job is currently due.
	Dequeue(ctx context.Context) (job Job, ok bool, err error)

	// Complete marks a claimed job as successfully delivered, removing it
	// from the queue.
	Complete(ctx context.Context, id string) error

	// Fail records a failed delivery attempt and reschedules the job for
	// nextAttemptAt (FR-3.4's backoff decides that time), or dead-letters
	// it if the caller has exhausted retries.
	Fail(ctx context.Context, id string, cause error, nextAttemptAt time.Time) error

	// Count returns the number of jobs not yet Complete'd (claimed or
	// not, due or not) — NFR-OBS-1's envelope_queue_depth, sampled
	// periodically rather than tracked via inline increment/decrement so
	// it can never drift from the queue's actual persisted state.
	Count(ctx context.Context) (int, error)
}
