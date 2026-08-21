package webhook

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/google/uuid"
)

// MemoryStore is a process-local, non-durable Store. It exists so Phase 2
// can compile and run against the real Store contract before Phase 3
// lands a durable implementation on Goose's sql module (FR-6.5) — delivery
// history is lost on process restart, so it must never be used once real
// tenants depend on dead-letter visibility.
type MemoryStore struct {
	mu            sync.Mutex
	subscriptions map[string]Subscription
	attempts      map[string][]DeliveryAttempt // keyed by subscription ID
}

// NewMemoryStore returns an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		subscriptions: make(map[string]Subscription),
		attempts:      make(map[string][]DeliveryAttempt),
	}
}

var _ Store = (*MemoryStore)(nil)

func (m *MemoryStore) CreateSubscription(ctx context.Context, sub Subscription) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if sub.ID == "" {
		return fmt.Errorf("webhook: subscription ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscriptions[sub.ID] = sub
	return nil
}

func (m *MemoryStore) ListSubscriptions(ctx context.Context, vhost string) ([]Subscription, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Subscription
	for _, sub := range m.subscriptions {
		if sub.Vhost == vhost {
			out = append(out, sub)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListSubscriptionsPage is the paginated variant PostgresStore's
// ListSubscriptionsPage implements against a real cursor-ordered query —
// see Store's doc for why both exist. This in-memory version sorts by ID
// (the same order ListSubscriptions now returns) and slices the requested
// window, so tests exercising a fake Store see the same page boundaries a
// real deployment would.
func (m *MemoryStore) ListSubscriptionsPage(ctx context.Context, vhost, cursor string, limit int) ([]Subscription, error) {
	all, err := m.ListSubscriptions(ctx, vhost)
	if err != nil {
		return nil, err
	}
	start := len(all)
	if cursor == "" {
		start = 0
	} else {
		for i, s := range all {
			if s.ID > cursor {
				start = i
				break
			}
		}
	}
	end := start + pageLimit(limit)
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], nil
}

func (m *MemoryStore) DisableSubscription(ctx context.Context, vhost, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	sub, ok := m.subscriptions[id]
	if !ok || sub.Vhost != vhost {
		return fmt.Errorf("webhook: subscription %q: %w", id, ErrNotFound)
	}
	sub.Disabled = true
	m.subscriptions[id] = sub
	return nil
}

func (m *MemoryStore) RecordAttempt(ctx context.Context, attempt DeliveryAttempt) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if attempt.SubscriptionID == "" {
		return fmt.Errorf("webhook: attempt subscription ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Derive Vhost from the subscription itself, the same way PostgresStore
	// does — see that method's doc for why attempt.Vhost isn't trusted.
	if sub, ok := m.subscriptions[attempt.SubscriptionID]; ok {
		attempt.Vhost = sub.Vhost
	}
	attempt.ID = uuid.NewString()
	m.attempts[attempt.SubscriptionID] = append(m.attempts[attempt.SubscriptionID], attempt)
	return nil
}

func (m *MemoryStore) ListAttempts(ctx context.Context, vhost, subscriptionID string) ([]DeliveryAttempt, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	sub, ok := m.subscriptions[subscriptionID]
	if !ok || sub.Vhost != vhost {
		return nil, nil
	}
	out := make([]DeliveryAttempt, len(m.attempts[subscriptionID]))
	copy(out, m.attempts[subscriptionID])
	return out, nil
}

// ListAttemptsPage is the paginated variant of ListAttempts — see
// Store's doc for why both exist. attempts are already recorded in
// attempted-at order (RecordAttempt appends), so no re-sort is needed
// before slicing the requested window; cursor is the last-seen attempt's
// ID (RecordAttempt assigns one to every attempt, the same field
// PostgresStore's cursor addresses).
func (m *MemoryStore) ListAttemptsPage(ctx context.Context, vhost, subscriptionID, cursor string, limit int) ([]DeliveryAttempt, error) {
	all, err := m.ListAttempts(ctx, vhost, subscriptionID)
	if err != nil {
		return nil, err
	}
	start := len(all)
	if cursor == "" {
		start = 0
	} else {
		for i, a := range all {
			if a.ID == cursor {
				start = i + 1
				break
			}
		}
	}
	end := start + pageLimit(limit)
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], nil
}
