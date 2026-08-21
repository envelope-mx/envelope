package webhook

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryEventQueue is a process-local, non-durable EventQueue — for tests
// only, mirroring queue.MemoryBackend's role for queue.Backend. Delivery
// retries are lost on process restart, so it must never back a production
// Dispatcher.
type MemoryEventQueue struct {
	mu      sync.Mutex
	jobs    map[string]DeliveryJob
	claimed map[string]bool
}

// NewMemoryEventQueue returns an empty in-memory EventQueue.
func NewMemoryEventQueue() *MemoryEventQueue {
	return &MemoryEventQueue{
		jobs:    make(map[string]DeliveryJob),
		claimed: make(map[string]bool),
	}
}

var _ EventQueue = (*MemoryEventQueue)(nil)

func (m *MemoryEventQueue) Enqueue(ctx context.Context, job DeliveryJob) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if job.ID == "" {
		return fmt.Errorf("webhook: delivery job ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job.ID] = job
	return nil
}

func (m *MemoryEventQueue) Dequeue(ctx context.Context) (DeliveryJob, bool, error) {
	if ctx.Err() != nil {
		return DeliveryJob{}, false, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var best *DeliveryJob
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
		return DeliveryJob{}, false, nil
	}

	m.claimed[best.ID] = true
	return *best, true, nil
}

func (m *MemoryEventQueue) Complete(ctx context.Context, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[id]; !ok {
		return fmt.Errorf("webhook: delivery job %q not found", id)
	}
	delete(m.jobs, id)
	delete(m.claimed, id)
	return nil
}

// Empty reports whether every enqueued job has been Complete'd (delivered
// or dead-lettered) — test-only convenience for waiting on Run's background
// loop to finish draining a fixed batch of jobs.
func (m *MemoryEventQueue) Empty() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jobs) == 0
}

func (m *MemoryEventQueue) Fail(ctx context.Context, id string, cause error, nextAttemptAt time.Time) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return fmt.Errorf("webhook: delivery job %q not found", id)
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
