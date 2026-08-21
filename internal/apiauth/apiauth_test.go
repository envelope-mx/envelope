package apiauth_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/isaiahiroko/envelope/internal/apiauth"
)

func TestGenerateTokenRoundTripsThroughHash(t *testing.T) {
	raw, hash, err := apiauth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(raw, apiauth.TokenPrefix) {
		t.Fatalf("expected token to start with %q, got %q", apiauth.TokenPrefix, raw)
	}
	if hash != apiauth.HashToken(raw) {
		t.Fatalf("HashToken(raw) is not stable/deterministic")
	}

	raw2, hash2, err := apiauth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if raw == raw2 || hash == hash2 {
		t.Fatal("expected two generated tokens to be distinct")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !apiauth.ConstantTimeEqual("abc", "abc") {
		t.Fatal("expected equal strings to compare equal")
	}
	if apiauth.ConstantTimeEqual("abc", "abd") {
		t.Fatal("expected different strings to compare unequal")
	}
	if apiauth.ConstantTimeEqual("abc", "ab") {
		t.Fatal("expected different-length strings to compare unequal")
	}
}

func TestMemoryStoreCreateAuthenticateRevoke(t *testing.T) {
	ctx := context.Background()
	s := apiauth.NewMemoryStore()

	raw, hash, err := apiauth.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	created, err := s.CreateToken(ctx, "1", "a.example", "ci", hash)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if created.AccountID != "a.example" || created.Label != "ci" {
		t.Fatalf("unexpected created token: %+v", created)
	}

	got, ok, err := s.Authenticate(ctx, apiauth.HashToken(raw))
	if err != nil || !ok || got.ID != "1" {
		t.Fatalf("Authenticate: got=%+v ok=%v err=%v", got, ok, err)
	}

	if _, ok, err := s.Authenticate(ctx, apiauth.HashToken("env_wrong")); err != nil || ok {
		t.Fatalf("expected Authenticate to fail for an unknown token: ok=%v err=%v", ok, err)
	}

	tokens, err := s.ListTokens(ctx, "a.example")
	if err != nil || len(tokens) != 1 {
		t.Fatalf("ListTokens: %+v, err=%v", tokens, err)
	}

	if err := s.RevokeToken(ctx, "wrong-account", "1"); err == nil {
		t.Fatal("expected revoking under the wrong account to fail")
	}
	if err := s.RevokeToken(ctx, "a.example", "1"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, ok, _ := s.Authenticate(ctx, apiauth.HashToken(raw)); ok {
		t.Fatal("expected a revoked token to no longer authenticate")
	}
}

func TestMemoryStoreListTokensPageSweepFindsEveryRowOnce(t *testing.T) {
	ctx := context.Background()
	s := apiauth.NewMemoryStore()

	const total = 5
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("tok-%d", i)
		if _, err := s.CreateToken(ctx, id, "a.example", "ci", "hash-"+id); err != nil {
			t.Fatalf("CreateToken %d: %v", i, err)
		}
	}
	if _, err := s.CreateToken(ctx, "other", "b.example", "ci", "hash-other"); err != nil {
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
