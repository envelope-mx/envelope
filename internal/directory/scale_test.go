package directory_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/dbtest"
	"github.com/isaiahiroko/envelope/internal/directory"
)

// TestScaleTo100kVhosts is TRD §6.1's "validate vhost count to 100k+ rows
// in load testing" target, measured for real rather than estimated. It's
// gated behind ENVELOPE_RUN_SCALE_TESTS (on top of the usual
// ENVELOPE_TEST_POSTGRES_DSN gate) since bulk-inserting 100k rows and
// scanning them isn't something every `go test ./...` run should pay for
// — opt in explicitly to re-validate at scale:
//
//	ENVELOPE_RUN_SCALE_TESTS=1 ENVELOPE_TEST_POSTGRES_DSN=... \
//	  go test ./internal/directory/... -run TestScaleTo100kVhosts -v
//
// Rows are bulk-inserted via a single raw SQL statement (Postgres
// generate_series), not 100k individual Service.CreateVhost calls: each
// CreateVhost generates a real 2048-bit RSA key pair, which is the
// bottleneck for vhost *creation* throughput, not what this target is
// about (query/lookup performance at volume). generate_series avoids
// spending the whole test budget on RSA keygen instead of the thing being
// measured.
func TestScaleTo100kVhosts(t *testing.T) {
	if os.Getenv("ENVELOPE_RUN_SCALE_TESTS") == "" {
		t.Skip("ENVELOPE_RUN_SCALE_TESTS not set; skipping (see test doc to opt in)")
	}
	db := dbtest.DB(t)
	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const targetRows = 100_000
	runID := uuid.NewString()

	var existing int64
	if err := db.Table("vhosts").Count(&existing).Error; err != nil {
		t.Fatalf("count existing rows: %v", err)
	}
	t.Logf("vhosts table has %d existing rows before this run's insert", existing)

	insertStart := time.Now()
	sql := fmt.Sprintf(`
		INSERT INTO vhosts (id, created_at, updated_at, domain, active, max_message_bytes, daily_quota, spam_reject_threshold, spam_quarantine_threshold)
		SELECT
			gen_random_uuid()::text,
			now(), now(),
			'scale-test-%s-' || g || '.test',
			true, 26214400, 1000, 15, 6
		FROM generate_series(1, %d) AS g
	`, runID, targetRows)
	if err := db.Exec(sql).Error; err != nil {
		t.Fatalf("bulk insert %d rows: %v", targetRows, err)
	}
	insertDuration := time.Since(insertStart)
	t.Logf("bulk-inserted %d rows in %v", targetRows, insertDuration)

	var total int64
	if err := db.Table("vhosts").Count(&total).Error; err != nil {
		t.Fatalf("count total rows: %v", err)
	}
	t.Logf("vhosts table now has %d total rows", total)

	svc := directory.New(db, testEncryptor(t))
	ctx := context.Background()

	// Point lookup by domain (the hot path: every RCPT TO / AUTH does
	// this) — the query every inbound/submission connection actually
	// depends on scaling well.
	targetDomain := fmt.Sprintf("scale-test-%s-%d.test", runID, targetRows/2)
	lookupStart := time.Now()
	if !svc.VhostActive(ctx, targetDomain) {
		t.Fatalf("expected bulk-inserted domain %q to be found and active", targetDomain)
	}
	lookupDuration := time.Since(lookupStart)
	t.Logf("VhostActive point lookup at %d rows: %v", total, lookupDuration)
	if lookupDuration > 500*time.Millisecond {
		t.Errorf("point lookup at %d rows took %v, expected well under 500ms (idx_vhosts_domain should make this O(log n))", total, lookupDuration)
	}

	// A single default-sized page (this is what VhostController.ListVhosts
	// actually does per request now — see directory.Service.ListVhosts's
	// doc): this is the number that matters for API latency at scale, not
	// a full-table scan.
	pageStart := time.Now()
	page, err := svc.ListVhosts(ctx, "", directory.DefaultVhostPageSize)
	if err != nil {
		t.Fatalf("ListVhosts (one page): %v", err)
	}
	pageDuration := time.Since(pageStart)
	t.Logf("ListVhosts one page (limit=%d) at %d total rows: %v, returned %d rows",
		directory.DefaultVhostPageSize, total, pageDuration, len(page))
	if pageDuration > 500*time.Millisecond {
		t.Errorf("one page at %d rows took %v, expected well under 500ms", total, pageDuration)
	}

	// Full pagination sweep — this is the number that would have been
	// ListVhosts's old unbounded-query cost (measured before this fix at
	// ~11s for 100k rows; see docs/ENVELOPE.md Phase 6), now paid in
	// bounded per-page increments instead of one unbounded call.
	sweepStart := time.Now()
	seen := 0
	cursor := ""
	for {
		p, err := svc.ListVhosts(ctx, cursor, directory.MaxVhostPageSize)
		if err != nil {
			t.Fatalf("ListVhosts (sweep): %v", err)
		}
		seen += len(p)
		if len(p) < directory.MaxVhostPageSize {
			break
		}
		cursor = p[len(p)-1].ID
	}
	sweepDuration := time.Since(sweepStart)
	t.Logf("full pagination sweep at %d total rows: %v across %d rows seen", total, sweepDuration, seen)
}
