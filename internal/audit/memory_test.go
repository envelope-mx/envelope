package audit_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/isaiahiroko/envelope/internal/audit"
)

func TestMemoryStoreRecordAndList(t *testing.T) {
	ctx := context.Background()
	s := audit.NewMemoryStore()

	if err := s.Record(ctx, audit.Entry{Actor: "admin", Action: "vhost.create", Target: "", Detail: "example.test"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Record(ctx, audit.Entry{Actor: "admin", Action: "mailbox.create", Target: "vhost-1", Detail: "alice"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := s.Record(ctx, audit.Entry{Actor: "vhost:vhost-1", Action: "mailbox.delete", Target: "vhost-1", Detail: "alice"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := s.List(ctx, "vhost-1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries for vhost-1, got %+v", entries)
	}
	// Newest first.
	if entries[0].Action != "mailbox.delete" || entries[1].Action != "mailbox.create" {
		t.Fatalf("expected newest-first order, got %+v", entries)
	}

	platform, err := s.List(ctx, "")
	if err != nil || len(platform) != 1 || platform[0].Action != "vhost.create" {
		t.Fatalf("expected 1 platform-level entry, got %+v (err %v)", platform, err)
	}
}

func TestMemoryStoreListPageSweepFindsEveryRowOnceNewestFirst(t *testing.T) {
	ctx := context.Background()
	s := audit.NewMemoryStore()

	const total = 5
	for i := 0; i < total; i++ {
		err := s.Record(ctx, audit.Entry{Actor: "admin", Action: "mailbox.create", Target: "vhost-1", Detail: fmt.Sprintf("mailbox-%d", i)})
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	seen := make(map[string]bool)
	var order []string
	cursor := ""
	for {
		page, err := s.ListPage(ctx, "vhost-1", cursor, 2)
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
		want := fmt.Sprintf("mailbox-%d", total-1-i)
		if detail != want {
			t.Fatalf("expected newest-first order across pages, got %v", order)
		}
	}
}
