package ratelimit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/dbtest"
	"github.com/isaiahiroko/envelope/internal/ratelimit"
)

func newLimiter(t *testing.T) *ratelimit.PostgresLimiter {
	t.Helper()
	db := dbtest.DB(t)
	if err := ratelimit.MigratePostgres(db); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	return ratelimit.NewPostgresLimiter(db)
}

// uniqueKey avoids collisions with leftover rows from previous runs
// against a shared, un-truncated database — the same reasoning as
// internal/directory/service_test.go's uniqueDomain.
func uniqueKey(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%s", t.Name(), uuid.NewString())
}

func TestPostgresAllowConsumesCapacityThenDenies(t *testing.T) {
	l := newLimiter(t)
	key := uniqueKey(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		allowed, err := l.Allow(ctx, key, 3, 0)
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !allowed {
			t.Fatalf("expected Allow to succeed on request %d", i+1)
		}
	}

	allowed, err := l.Allow(ctx, key, 3, 0)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if allowed {
		t.Fatal("expected Allow to fail once capacity is exhausted")
	}
}

func TestPostgresAllowRefillsOverTime(t *testing.T) {
	l := newLimiter(t)
	key := uniqueKey(t)
	ctx := context.Background()

	clock := time.Now()
	l.SetNowFunc(func() time.Time { return clock })

	if allowed, err := l.Allow(ctx, key, 2, 1); err != nil || !allowed {
		t.Fatalf("first Allow: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := l.Allow(ctx, key, 2, 1); err != nil || !allowed {
		t.Fatalf("second Allow: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := l.Allow(ctx, key, 2, 1); err != nil || allowed {
		t.Fatalf("expected bucket to be empty: allowed=%v err=%v", allowed, err)
	}

	clock = clock.Add(1500 * time.Millisecond) // refills 1.5 tokens
	l.SetNowFunc(func() time.Time { return clock })

	if allowed, err := l.Allow(ctx, key, 2, 1); err != nil || !allowed {
		t.Fatalf("expected a token to be available after refill: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := l.Allow(ctx, key, 2, 1); err != nil || allowed {
		t.Fatalf("expected only one token to have refilled: allowed=%v err=%v", allowed, err)
	}
}

func TestPostgresAllowSharedAcrossInstances(t *testing.T) {
	// FR-2.3's whole point: two separate limiter instances (standing in
	// for two replicas) must share the same bucket for a given key.
	db := dbtest.DB(t)
	if err := ratelimit.MigratePostgres(db); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	l1 := ratelimit.NewPostgresLimiter(db)
	l2 := ratelimit.NewPostgresLimiter(dbtest.DB(t))

	key := uniqueKey(t)
	ctx := context.Background()

	if allowed, err := l1.Allow(ctx, key, 1, 0); err != nil || !allowed {
		t.Fatalf("l1.Allow: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := l2.Allow(ctx, key, 1, 0); err != nil || allowed {
		t.Fatalf("expected l2 to see the capacity l1 already consumed: allowed=%v err=%v", allowed, err)
	}
}

func TestPostgresAllowDifferentKeysAreIndependent(t *testing.T) {
	l := newLimiter(t)
	ctx := context.Background()
	keyA, keyB := uniqueKey(t)+"-a", uniqueKey(t)+"-b"

	if allowed, err := l.Allow(ctx, keyA, 1, 0); err != nil || !allowed {
		t.Fatalf("keyA Allow: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := l.Allow(ctx, keyB, 1, 0); err != nil || !allowed {
		t.Fatalf("keyB should be unaffected by keyA's consumption: allowed=%v err=%v", allowed, err)
	}
}
