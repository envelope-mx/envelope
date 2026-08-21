package audit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/envelope-mx/envelope/internal/audit"
	"github.com/envelope-mx/envelope/internal/dbtest"
)

func newPostgresStore(t *testing.T) *audit.PostgresStore {
	t.Helper()
	db := dbtest.DB(t)
	if err := audit.MigratePostgres(db); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	return audit.NewPostgresStore(db)
}

func TestPostgresRecordAndList(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)

	target := "vhost-" + t.Name() + "-" + uuid.NewString()
	if err := s.Record(ctx, audit.Entry{Actor: "admin", Action: "vhost.deactivate", Target: target, Detail: "test"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Record(ctx, audit.Entry{Actor: "admin", Action: "mailbox.create", Target: target, Detail: "alice"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := s.List(ctx, target)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %+v", entries)
	}
	if entries[0].Action != "mailbox.create" {
		t.Fatalf("expected newest-first order, got %+v", entries)
	}
}

// TestPostgresListPageSweep exercises FR-5.4's cursor pagination the same
// way internal/directory's TestListMailboxesPage does: every entry must
// appear exactly once across the full sweep, in the same newest-first
// order List returns, regardless of page boundaries. Entries are recorded
// with explicit, strictly increasing At values (rather than relying on
// time.Now()'s resolution between fast successive Record calls) so the
// (at, id) tiebreak ordering ListPage's doc describes is exercised
// deterministically.
func TestPostgresListPageSweep(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)
	target := "vhost-" + t.Name() + "-" + uuid.NewString()

	const total = 5
	base := time.Now()
	for i := 0; i < total; i++ {
		err := s.Record(ctx, audit.Entry{
			Actor: "admin", Action: "mailbox.create", Target: target, Detail: fmt.Sprintf("mailbox-%d", i),
			At: base.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	seen := make(map[string]bool)
	var order []string
	cursor := ""
	for {
		page, err := s.ListPage(ctx, target, cursor, 2)
		if err != nil {
			t.Fatalf("ListPage: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if seen[e.ID] {
				t.Fatalf("entry %q returned on more than one page", e.ID)
			}
			seen[e.ID] = true
			order = append(order, e.Detail)
		}
		if len(page) < 2 {
			break
		}
		cursor = page[len(page)-1].ID
	}
	if len(seen) != total {
		t.Fatalf("expected %d distinct entries across all pages, got %d", total, len(seen))
	}
	for i, detail := range order {
		want := fmt.Sprintf("mailbox-%d", total-1-i) // newest (highest i) first
		if detail != want {
			t.Fatalf("expected newest-first order across pages, got %v", order)
		}
	}
}
