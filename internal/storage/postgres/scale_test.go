package postgres_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/envelope-mx/envelope/internal/dbtest"
	"github.com/envelope-mx/envelope/internal/storage/postgres"
)

// TestScaleMessageBodyVolume is TRD R3's still-open literal question,
// finally measured: "an actual number for the messages table specifically
// (body storage volume, FR-4.4), which needs a dedicated test with
// realistic body sizes at real volume (many GB)" (index/TRD.md §10 R3).
// TestScaleTo100kVhosts already answered the adjacent §6.1 vhost-count
// target; this is the messages-table half that was explicitly left
// unresolved by that pass.
//
// Gated behind ENVELOPE_RUN_SCALE_TESTS, the same opt-in as
// TestScaleTo100kVhosts, for the same reason — bulk-inserting several GB
// and scanning it isn't something every `go test ./...` run should pay
// for:
//
//	ENVELOPE_RUN_SCALE_TESTS=1 ENVELOPE_TEST_POSTGRES_DSN=... \
//	  go test ./internal/storage/postgres/... -run TestScaleMessageBodyVolume -v
//
// Rows are bulk-inserted via a single raw SQL statement (Postgres
// generate_series + repeat(...)::bytea), not targetRows individual
// Backend.Write calls, the same reasoning TestScaleTo100kVhosts gives for
// bulk-inserting vhosts instead of calling CreateVhost in a loop: this test
// measures query/read performance at volume, not insert-call overhead.
func TestScaleMessageBodyVolume(t *testing.T) {
	if os.Getenv("ENVELOPE_RUN_SCALE_TESTS") == "" {
		t.Skip("ENVELOPE_RUN_SCALE_TESTS not set; skipping (see test doc to opt in)")
	}
	db := dbtest.DB(t)
	if err := postgres.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	const (
		targetRows = 20_000
		// bodyBytes is TRD R3's "realistic body size" — between a
		// plain-text message and one with a modest attachment, not
		// FR-4.4's absolute ceiling (this test measures whether the
		// current guidance holds at a representative size and volume, not
		// the largest single message Postgres could theoretically store).
		bodyBytes = 200 * 1024
	)

	runID := uuid.NewString()
	vhost := fmt.Sprintf("scale-body-%s.test", runID)
	mailbox := "INBOX"

	insertStart := time.Now()
	sql := fmt.Sprintf(`
		INSERT INTO messages (id, created_at, updated_at, vhost, mailbox, body, size, flags)
		SELECT
			gen_random_uuid()::text,
			now(), now(),
			'%s', '%s',
			repeat('a', %d)::bytea,
			%d,
			''
		FROM generate_series(1, %d) AS g
	`, vhost, mailbox, bodyBytes, bodyBytes, targetRows)
	if err := db.Exec(sql).Error; err != nil {
		t.Fatalf("bulk insert %d rows: %v", targetRows, err)
	}
	insertDuration := time.Since(insertStart)
	totalGB := float64(int64(targetRows)*int64(bodyBytes)) / (1 << 30)
	t.Logf("bulk-inserted %d message rows (%.2f GB total body volume) in %v", targetRows, totalGB, insertDuration)

	store := postgres.New(db)
	ctx := context.Background()

	// List (per-mailbox listing — what IMAP's SELECT/FETCH-headers path
	// actually does) excludes the body column, so this measures index/
	// row-scan cost, not bytea transfer.
	listStart := time.Now()
	metas, err := store.List(ctx, vhost, mailbox)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	listDuration := time.Since(listStart)
	t.Logf("List (metadata only) for %d rows: %v", len(metas), listDuration)
	if len(metas) != targetRows {
		t.Fatalf("expected %d rows, got %d", targetRows, len(metas))
	}
	if listDuration > 2*time.Second {
		t.Errorf("List at %d rows / %.2fGB took %v, expected well under 2s (metadata-only, "+
			"should not be reading body bytes)", targetRows, totalGB, listDuration)
	}

	// Read a single message body — the actual bytea transfer cost IMAP
	// FETCH pays per message, at this representative body size.
	readStart := time.Now()
	rc, err := store.Read(ctx, metas[targetRows/2].Ref)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	body, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	readDuration := time.Since(readStart)
	if len(body) != bodyBytes {
		t.Errorf("expected body of %d bytes, got %d", bodyBytes, len(body))
	}
	t.Logf("Read single %d-byte body: %v", bodyBytes, readDuration)
	if readDuration > 500*time.Millisecond {
		t.Errorf("single-message Read at body size %d took %v, expected well under 500ms", bodyBytes, readDuration)
	}

	// ListVhost — retention purge's (internal/retention) and GDPR export's
	// (DataController.Export) hot path, across every mailbox for this
	// vhost (only one here, but exercises the same query NFR-COMP-1/
	// NFR-COMP-2 depend on at this row count).
	listVhostStart := time.Now()
	all, err := store.ListVhost(ctx, vhost)
	if err != nil {
		t.Fatalf("ListVhost: %v", err)
	}
	listVhostDuration := time.Since(listVhostStart)
	t.Logf("ListVhost (metadata only) for %d rows: %v", len(all), listVhostDuration)
	if len(all) != targetRows {
		t.Errorf("expected %d rows from ListVhost, got %d", targetRows, len(all))
	}
	if listVhostDuration > 2*time.Second {
		t.Errorf("ListVhost at %d rows took %v, expected well under 2s", targetRows, listVhostDuration)
	}
}
