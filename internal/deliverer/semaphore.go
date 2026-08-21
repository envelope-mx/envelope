package deliverer

import (
	"context"
	"sync"
)

// domainSemaphores caps concurrent delivery attempts per destination
// domain (FR-3.5: default 5), so one slow or congested destination can't
// exhaust worker capacity for every other destination. Each domain gets
// its own buffered channel acting as a counting semaphore, created lazily
// on first use.
type domainSemaphores struct {
	mu    sync.Mutex
	sems  map[string]chan struct{}
	limit int
}

func newDomainSemaphores(limit int) *domainSemaphores {
	if limit <= 0 {
		limit = 1
	}
	return &domainSemaphores{sems: make(map[string]chan struct{}), limit: limit}
}

// acquire blocks until a slot for domain is available or ctx is done. The
// returned release func must be called exactly once to free the slot.
func (d *domainSemaphores) acquire(ctx context.Context, domain string) (release func(), err error) {
	d.mu.Lock()
	sem, ok := d.sems[domain]
	if !ok {
		sem = make(chan struct{}, d.limit)
		d.sems[domain] = sem
	}
	d.mu.Unlock()

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
