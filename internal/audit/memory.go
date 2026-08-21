package audit

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore is a process-local, non-durable Store — for tests only.
type MemoryStore struct {
	mu      sync.Mutex
	entries []Entry
}

// NewMemoryStore returns an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

var _ Store = (*MemoryStore)(nil)

func (m *MemoryStore) Record(ctx context.Context, entry Entry) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if entry.At.IsZero() {
		entry.At = time.Now()
	}
	entry.ID = uuid.NewString()

	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entry)
	return nil
}

func (m *MemoryStore) List(ctx context.Context, target string) ([]Entry, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Entry
	for i := len(m.entries) - 1; i >= 0; i-- {
		if m.entries[i].Target == target {
			out = append(out, m.entries[i])
		}
	}
	return out, nil
}

// ListPage is the paginated variant of List — see Store's doc for why both
// exist. m.entries is already append-ordered (oldest first), and List
// above walks it backwards for newest-first order, so cursor here is
// simply "how many already-seen entries to skip past" once found.
func (m *MemoryStore) ListPage(ctx context.Context, target, cursor string, limit int) ([]Entry, error) {
	all, err := m.List(ctx, target)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxPageSize {
		limit = DefaultPageSize
	}
	start := len(all)
	if cursor == "" {
		start = 0
	} else {
		for i, e := range all {
			if e.ID == cursor {
				start = i + 1
				break
			}
		}
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], nil
}
