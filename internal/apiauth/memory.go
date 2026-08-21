package apiauth

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MemoryStore is a process-local, non-durable Store — for tests only.
type MemoryStore struct {
	mu     sync.Mutex
	tokens map[string]tokenEntry // keyed by ID
}

type tokenEntry struct {
	Token
	Hash string
}

// NewMemoryStore returns an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{tokens: make(map[string]tokenEntry)}
}

var _ Store = (*MemoryStore)(nil)

func (m *MemoryStore) CreateToken(ctx context.Context, id, accountID, label, tokenHash string) (Token, error) {
	if ctx.Err() != nil {
		return Token{}, ctx.Err()
	}
	if id == "" {
		return Token{}, fmt.Errorf("apiauth: token ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	tok := Token{ID: id, AccountID: accountID, Label: label, CreatedAt: time.Now()}
	m.tokens[id] = tokenEntry{Token: tok, Hash: tokenHash}
	return tok, nil
}

func (m *MemoryStore) Authenticate(ctx context.Context, tokenHash string) (Token, bool, error) {
	if ctx.Err() != nil {
		return Token{}, false, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.tokens {
		if e.Hash == tokenHash {
			return e.Token, true, nil
		}
	}
	return Token{}, false, nil
}

func (m *MemoryStore) ListTokens(ctx context.Context, accountID string) ([]Token, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Token
	for _, e := range m.tokens {
		if e.AccountID == accountID {
			out = append(out, e.Token)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListTokensPage is the paginated variant of ListTokens — see Store's doc
// for why both exist. Sorts by ID (the same order ListTokens now returns)
// and slices the requested window, so tests exercising a fake Store see
// the same page boundaries a real deployment would.
func (m *MemoryStore) ListTokensPage(ctx context.Context, accountID, cursor string, limit int) ([]Token, error) {
	all, err := m.ListTokens(ctx, accountID)
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
		for i, t := range all {
			if t.ID > cursor {
				start = i
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

func (m *MemoryStore) RevokeToken(ctx context.Context, accountID, id string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tokens[id]
	if !ok || e.AccountID != accountID {
		return fmt.Errorf("apiauth: token %q: %w", id, ErrNotFound)
	}
	delete(m.tokens, id)
	return nil
}
