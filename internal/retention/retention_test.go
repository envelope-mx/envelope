package retention_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/retention"
	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/storage/maildir"
)

// fakeLister is a narrow, in-memory stand-in for *directory.Service —
// retention.Purger only needs ListVhosts, so tests don't need Postgres to
// exercise the purge logic itself (Postgres-backed storage.Store.ListVhost
// is covered separately in internal/storage/postgres's own tests).
type fakeLister struct {
	vhosts []directory.Vhost
}

func (f *fakeLister) ListVhosts(_ context.Context, _ string, _ int) ([]directory.Vhost, error) {
	return f.vhosts, nil
}

func TestSweepDeletesOnlyMessagesOlderThanRetention(t *testing.T) {
	store := maildir.New(t.TempDir())
	ctx := context.Background()

	if _, err := store.Write(ctx, "example.com", "alice/INBOX", strings.NewReader("old")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	oldRefs, err := store.ListVhost(ctx, "example.com")
	if err != nil || len(oldRefs) != 1 {
		t.Fatalf("ListVhost setup: %v, %+v", err, oldRefs)
	}

	if _, err := store.Write(ctx, "example.com", "alice/INBOX", strings.NewReader("new")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	lister := &fakeLister{vhosts: []directory.Vhost{{ID: "v1", Domain: "example.com", RetentionDays: 30}}}
	fixedNow := time.Now()
	p := &retention.Purger{
		Directory: lister,
		Store:     store,
		Now:       func() time.Time { return fixedNow },
	}

	// Make the "old" message look 31 days old by backdating its mtime —
	// maildir derives CreatedAt from the file's mtime (see
	// maildir.Backend.List's doc).
	backdate(t, store, oldRefs[0].Ref, fixedNow.AddDate(0, 0, -31))

	p.Sweep(ctx)

	got, err := store.ListVhost(ctx, "example.com")
	if err != nil {
		t.Fatalf("ListVhost after sweep: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 message to survive the sweep, got %d: %+v", len(got), got)
	}
	if _, err := store.Read(ctx, oldRefs[0].Ref); err == nil {
		t.Fatalf("expected the 31-day-old message to be purged, but it still exists")
	}
}

func TestSweepAppliesPlatformDefaultWhenVhostUnconfigured(t *testing.T) {
	store := maildir.New(t.TempDir())
	ctx := context.Background()

	if _, err := store.Write(ctx, "example.com", "alice/INBOX", strings.NewReader("old")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	refs, err := store.ListVhost(ctx, "example.com")
	if err != nil || len(refs) != 1 {
		t.Fatalf("ListVhost setup: %v, %+v", err, refs)
	}

	// RetentionDays 0 (unconfigured) -> the Purger's DefaultRetentionDays
	// override, not "never purge".
	lister := &fakeLister{vhosts: []directory.Vhost{{ID: "v1", Domain: "example.com", RetentionDays: 0}}}
	fixedNow := time.Now()
	p := &retention.Purger{
		Directory:            lister,
		Store:                store,
		Now:                  func() time.Time { return fixedNow },
		DefaultRetentionDays: 10,
	}
	backdate(t, store, refs[0].Ref, fixedNow.AddDate(0, 0, -11))

	p.Sweep(ctx)

	if _, err := store.Read(ctx, refs[0].Ref); err == nil {
		t.Fatalf("expected the message to be purged under the platform default retention")
	}
}

func TestSweepDoesNotTouchOtherVhosts(t *testing.T) {
	store := maildir.New(t.TempDir())
	ctx := context.Background()

	if _, err := store.Write(ctx, "other.example", "alice/INBOX", strings.NewReader("old")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	refs, err := store.ListVhost(ctx, "other.example")
	if err != nil || len(refs) != 1 {
		t.Fatalf("ListVhost setup: %v, %+v", err, refs)
	}
	fixedNow := time.Now()
	backdate(t, store, refs[0].Ref, fixedNow.AddDate(0, -1, 0))

	// Only "example.com" is a known vhost — "other.example" isn't in the
	// Directory's own list at all (e.g. deactivated/deleted), so it must
	// never be swept, regardless of how old its messages are.
	lister := &fakeLister{vhosts: []directory.Vhost{{ID: "v1", Domain: "example.com", RetentionDays: 1}}}
	p := &retention.Purger{Directory: lister, Store: store, Now: func() time.Time { return fixedNow }}

	p.Sweep(ctx)

	if _, err := store.Read(ctx, refs[0].Ref); err != nil {
		t.Fatalf("expected other.example's message to survive (not a listed vhost), got: %v", err)
	}
}

// backdate rewrites ref's file mtime directly — maildir.Backend has no
// "set CreatedAt" API of its own (mtime is set naturally at delivery
// time), so tests reach around it the same way they'd reach around any
// other backend-internal timestamp.
func backdate(t *testing.T, store *maildir.Backend, ref storage.MessageRef, when time.Time) {
	t.Helper()
	metas, err := store.List(context.Background(), ref.Vhost, ref.Mailbox)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, m := range metas {
		if m.Ref.Key == ref.Key {
			found = true
		}
	}
	if !found {
		t.Fatalf("ref %+v not found via List", ref)
	}
	if err := store.SetModTimeForTest(ref, when); err != nil {
		t.Fatalf("SetModTimeForTest: %v", err)
	}
}
