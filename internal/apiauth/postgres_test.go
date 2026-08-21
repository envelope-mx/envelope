package apiauth_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/envelope-mx/envelope/internal/apiauth"
	"github.com/envelope-mx/envelope/internal/dbtest"
)

func newPostgresStore(t *testing.T) *apiauth.PostgresStore {
	t.Helper()
	db := dbtest.DB(t)
	if err := apiauth.MigratePostgres(db); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	dbtest.Truncate(t, db, "api_tokens")
	return apiauth.NewPostgresStore(db)
}

func TestPostgresCreateAuthenticateRevoke(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)

	id := uuid.NewString()
	raw, hash, err := apiauth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, err := s.CreateToken(ctx, id, "a.example", "ci", hash); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	got, ok, err := s.Authenticate(ctx, apiauth.HashToken(raw))
	if err != nil || !ok || got.ID != id || got.AccountID != "a.example" {
		t.Fatalf("Authenticate: got=%+v ok=%v err=%v", got, ok, err)
	}

	tokens, err := s.ListTokens(ctx, "a.example")
	if err != nil || len(tokens) != 1 {
		t.Fatalf("ListTokens: %+v err=%v", tokens, err)
	}

	if err := s.RevokeToken(ctx, id, "wrong-account-for-this-id"); err == nil {
		t.Fatal("expected revoking with a mismatched (account, id) pair to fail")
	}
	if err := s.RevokeToken(ctx, "a.example", id); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, ok, _ := s.Authenticate(ctx, apiauth.HashToken(raw)); ok {
		t.Fatal("expected a revoked token to no longer authenticate")
	}
}

// TestPostgresListTokensPage exercises FR-5.4's cursor pagination the same
// way internal/directory's TestListMailboxesPage does: every token must
// appear exactly once across the full sweep, regardless of page
// boundaries.
func TestPostgresListTokensPage(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)

	const total = 5
	for i := 0; i < total; i++ {
		_, hash, err := apiauth.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		if _, err := s.CreateToken(ctx, uuid.NewString(), "a.example", "ci", hash); err != nil {
			t.Fatalf("CreateToken %d: %v", i, err)
		}
	}
	_, otherHash, err := apiauth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if _, err := s.CreateToken(ctx, uuid.NewString(), "b.example", "ci", otherHash); err != nil {
		t.Fatalf("CreateToken (other vhost): %v", err)
	}

	seen := make(map[string]bool)
	cursor := ""
	for {
		page, err := s.ListTokensPage(ctx, "a.example", cursor, 2)
		if err != nil {
			t.Fatalf("ListTokensPage: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, tok := range page {
			if seen[tok.ID] {
				t.Fatalf("token %q returned on more than one page", tok.ID)
			}
			seen[tok.ID] = true
		}
		if len(page) < 2 {
			break
		}
		cursor = page[len(page)-1].ID
	}
	if len(seen) != total {
		t.Fatalf("expected %d distinct tokens across all pages, got %d", total, len(seen))
	}
}

func TestPostgresAuthenticateUnknownTokenFails(t *testing.T) {
	s := newPostgresStore(t)
	_, ok, err := s.Authenticate(context.Background(), apiauth.HashToken("env_does-not-exist"))
	if err != nil || ok {
		t.Fatalf("expected no match for an unknown token: ok=%v err=%v", ok, err)
	}
}
