package maildir_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/storage/maildir"
)

func TestWriteCreatesStandardLayout(t *testing.T) {
	base := t.TempDir()
	b := maildir.New(base)
	ctx := context.Background()

	ref, err := b.Write(ctx, "example.com", "INBOX", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if ref.Vhost != "example.com" || ref.Mailbox != "INBOX" || ref.Key == "" {
		t.Fatalf("unexpected ref: %+v", ref)
	}

	mailboxDir := filepath.Join(base, "example.com", "INBOX")
	for _, sub := range []string{"new", "cur", "tmp"} {
		if fi, err := os.Stat(filepath.Join(mailboxDir, sub)); err != nil || !fi.IsDir() {
			t.Fatalf("expected dir %s/%s to exist: %v", mailboxDir, sub, err)
		}
	}

	if _, err := os.Stat(filepath.Join(mailboxDir, "new", ref.Key)); err != nil {
		t.Fatalf("expected message under new/: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(mailboxDir, "tmp")); len(entries) != 0 {
		t.Fatalf("tmp/ should be empty after delivery, got %d entries", len(entries))
	}
}

func TestReadRoundTrips(t *testing.T) {
	b := maildir.New(t.TempDir())
	ctx := context.Background()

	ref, err := b.Write(ctx, "example.com", "INBOX", strings.NewReader("the body"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	rc, err := b.Read(ctx, ref)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "the body" {
		t.Fatalf("got body %q, want %q", got, "the body")
	}
}

func TestListReflectsNewAndCur(t *testing.T) {
	b := maildir.New(t.TempDir())
	ctx := context.Background()

	ref, err := b.Write(ctx, "example.com", "INBOX", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	metas, err := b.List(ctx, "example.com", "INBOX")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 1 || metas[0].Ref.Key != ref.Key || len(metas[0].Flags) != 0 {
		t.Fatalf("unexpected list result: %+v", metas)
	}

	if err := b.UpdateFlags(ctx, ref, []string{storage.FlagSeen, storage.FlagFlagged}); err != nil {
		t.Fatalf("UpdateFlags: %v", err)
	}

	metas, err = b.List(ctx, "example.com", "INBOX")
	if err != nil {
		t.Fatalf("List after UpdateFlags: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("expected 1 message after UpdateFlags, got %d", len(metas))
	}
	if got := metas[0].Flags; len(got) != 2 || !contains(got, storage.FlagSeen) || !contains(got, storage.FlagFlagged) {
		t.Fatalf("unexpected flags: %v", got)
	}
}

func TestUpdateFlagsMovesNewToCur(t *testing.T) {
	base := t.TempDir()
	b := maildir.New(base)
	ctx := context.Background()

	ref, err := b.Write(ctx, "example.com", "INBOX", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	mailboxDir := filepath.Join(base, "example.com", "INBOX")
	if _, err := os.Stat(filepath.Join(mailboxDir, "new", ref.Key)); err != nil {
		t.Fatalf("expected message in new/ before UpdateFlags: %v", err)
	}

	if err := b.UpdateFlags(ctx, ref, []string{storage.FlagSeen}); err != nil {
		t.Fatalf("UpdateFlags: %v", err)
	}

	if _, err := os.Stat(filepath.Join(mailboxDir, "new", ref.Key)); !os.IsNotExist(err) {
		t.Fatalf("expected message removed from new/, stat err = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(mailboxDir, "cur"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly 1 entry in cur/, got %v (err %v)", entries, err)
	}
	if !strings.HasPrefix(entries[0].Name(), ref.Key+":2,") {
		t.Fatalf("unexpected cur/ filename: %s", entries[0].Name())
	}

	// Read and UpdateFlags again must still resolve the message by its
	// stable key even though it now lives in cur/.
	rc, err := b.Read(ctx, ref)
	if err != nil {
		t.Fatalf("Read after move to cur/: %v", err)
	}
	rc.Close()

	if err := b.UpdateFlags(ctx, ref, []string{storage.FlagSeen, storage.FlagDeleted}); err != nil {
		t.Fatalf("UpdateFlags (cur -> cur): %v", err)
	}
}

func TestDeleteRemovesMessage(t *testing.T) {
	b := maildir.New(t.TempDir())
	ctx := context.Background()

	ref, err := b.Write(ctx, "example.com", "INBOX", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := b.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := b.Read(ctx, ref); err == nil {
		t.Fatalf("expected Read to fail after Delete")
	}

	metas, err := b.List(ctx, "example.com", "INBOX")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 0 {
		t.Fatalf("expected empty mailbox after Delete, got %+v", metas)
	}
}

func TestNamespacingIsolatesVhostsAndMailboxes(t *testing.T) {
	b := maildir.New(t.TempDir())
	ctx := context.Background()

	if _, err := b.Write(ctx, "a.example", "INBOX", strings.NewReader("a")); err != nil {
		t.Fatalf("Write a: %v", err)
	}
	if _, err := b.Write(ctx, "b.example", "INBOX", strings.NewReader("b")); err != nil {
		t.Fatalf("Write b: %v", err)
	}
	if _, err := b.Write(ctx, "a.example", "Quarantine", strings.NewReader("q")); err != nil {
		t.Fatalf("Write quarantine: %v", err)
	}

	aInbox, err := b.List(ctx, "a.example", "INBOX")
	if err != nil || len(aInbox) != 1 {
		t.Fatalf("a.example/INBOX: %v, %+v", err, aInbox)
	}
	bInbox, err := b.List(ctx, "b.example", "INBOX")
	if err != nil || len(bInbox) != 1 {
		t.Fatalf("b.example/INBOX: %v, %+v", err, bInbox)
	}
	aQuarantine, err := b.List(ctx, "a.example", "Quarantine")
	if err != nil || len(aQuarantine) != 1 {
		t.Fatalf("a.example/Quarantine: %v, %+v", err, aQuarantine)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// TestListVhostFindsEveryMailboxNestedAndFlat covers ListVhost's harder
// case: mailbox identifiers are nested for per-account folders
// (directory.MailboxPath joins local-part and folder, e.g. "alice/INBOX")
// but flat for submission's Outbox — a fixed-depth listing would miss one
// or the other.
func TestListVhostFindsEveryMailboxNestedAndFlat(t *testing.T) {
	b := maildir.New(t.TempDir())
	ctx := context.Background()

	if _, err := b.Write(ctx, "example.com", "alice/INBOX", strings.NewReader("m1")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := b.Write(ctx, "example.com", "alice/Quarantine", strings.NewReader("m2")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := b.Write(ctx, "example.com", "bob/INBOX", strings.NewReader("m3")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := b.Write(ctx, "example.com", "Outbox", strings.NewReader("m4")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// A different vhost's messages must never appear.
	if _, err := b.Write(ctx, "other.example", "alice/INBOX", strings.NewReader("m5")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := b.ListVhost(ctx, "example.com")
	if err != nil {
		t.Fatalf("ListVhost: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 messages across example.com's mailboxes, got %d: %+v", len(got), got)
	}
	mailboxes := make(map[string]bool)
	for _, m := range got {
		mailboxes[m.Ref.Mailbox] = true
		if m.Ref.Vhost != "example.com" {
			t.Fatalf("ListVhost leaked another vhost's message: %+v", m)
		}
		if m.CreatedAt.IsZero() {
			t.Fatalf("expected a non-zero CreatedAt: %+v", m)
		}
	}
	for _, want := range []string{"alice/INBOX", "alice/Quarantine", "bob/INBOX", "Outbox"} {
		if !mailboxes[want] {
			t.Fatalf("expected mailbox %q in ListVhost results, got %+v", want, mailboxes)
		}
	}
}

func TestListVhostOnUnknownVhostReturnsEmpty(t *testing.T) {
	b := maildir.New(t.TempDir())
	got, err := b.ListVhost(context.Background(), "never-written.example")
	if err != nil {
		t.Fatalf("ListVhost: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no messages, got %+v", got)
	}
}
