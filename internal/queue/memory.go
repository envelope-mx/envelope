package queue

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryBackend is a process-local, non-durable Backend. It exists so
// Phase 2's protocol servers can compile and run against the real Backend
// contract before Phase 3 lands a durable implementation on Goose's queues
// module (FR-3.3) — it must never be used once real mail volume exists,
// since all jobs are lost on process restart.
type MemoryBackend struct {
	mu      sync.Mutex
	jobs    map[string]Job
	claimed map[string]bool
}

// NewMemoryBackend returns an empty in-memory Backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		jobs:    make(map[string]Job),
		claimed: make(map[string]bool),
	}
}

var _ Backend = (*MemoryBackend)(nil)

func (m *MemoryBackend) Enqueue(ctx context.Context, job Job) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if job.ID == "" {
		return fmt.Errorf("queue: job ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job.ID] = job
	return nil
}

// Dequeue claims the earliest-due unclaimed job whose NextAttemptAt has
// passed. A claimed job is held until Complete or Fail releases it, so
// concurrent callers never claim the same job twice.
func (m *MemoryBackend) Dequeue(ctx context.Context) (Job, bool, error) {
	if ctx.Err() != nil {
		return Job{}, false, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var best *Job
	for id, job := range m.jobs {
		if m.claimed[id] {
			continue
		}
		if job.NextAttemptAt.After(now) {
			continue
		}
		if best == nil || job.NextAttemptAt.Before(best.NextAttemptAt) {
			j := job
			best = &j
		}
	}
	if best == nil {
		return Job{}, false, nil
	}

	m.claimed[best.ID] = true
	return *best, true, nil
}

// Empty reports whether every enqueued job has been Complete'd — test-only
// convenience for waiting on a background consumer (e.g.
// internal/deliverer.Deliverer.Run) to finish draining a fixed batch of
// jobs.
func (m *MemoryBackend) Empty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jobs) == 0
}

func (m *MemoryBackend) Count(ctx context.Context) (int, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jobs), nil
}

func (m *MemoryBackend) Complete(ctx context.Context, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[id]; !ok {
		return fmt.Errorf("queue: job %q not found", id)
	}
	delete(m.jobs, id)
	delete(m.claimed, id)
	return nil
}

func (m *MemoryBackend) Fail(ctx context.Context, id string, cause error, nextAttemptAt time.Time) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return fmt.Errorf("queue: job %q not found", id)
	}

	job.Attempts++
	job.NextAttemptAt = nextAttemptAt
	if cause != nil {
		job.LastError = cause.Error()
	}
	m.jobs[id] = job
	delete(m.claimed, id)
	return nil
}
