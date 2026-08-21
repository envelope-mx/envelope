package postgres_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/isaiahiroko/envelope/internal/dbtest"
	"github.com/isaiahiroko/envelope/internal/storage"
	"github.com/isaiahiroko/envelope/internal/storage/postgres"
)

func newBackend(t *testing.T) *postgres.Backend {
	t.Helper()
	db := dbtest.DB(t)
	if err := postgres.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	dbtest.Truncate(t, db, "messages")
	return postgres.New(db)
}

func TestWriteAndRead(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	ref, err := b.Write(ctx, "example.com", "INBOX", strings.NewReader("the body"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if ref.Vhost != "example.com" || ref.Mailbox != "INBOX" || ref.Key == "" {
		t.Fatalf("unexpected ref: %+v", ref)
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

func TestList(t *testing.T) {
	b := newBackend(t)
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
}

func TestListVhost(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	if _, err := b.Write(ctx, "example.com", "alice/INBOX", strings.NewReader("m1")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := b.Write(ctx, "example.com", "Outbox", strings.NewReader("m2")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := b.Write(ctx, "other.example", "alice/INBOX", strings.NewReader("m3")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := b.ListVhost(ctx, "example.com")
	if err != nil {
		t.Fatalf("ListVhost: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 messages for example.com, got %d: %+v", len(got), got)
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
	if !mailboxes["alice/INBOX"] || !mailboxes["Outbox"] {
		t.Fatalf("expected both alice/INBOX and Outbox, got %+v", mailboxes)
	}
}

func TestUpdateFlags(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	ref, err := b.Write(ctx, "example.com", "INBOX", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := b.UpdateFlags(ctx, ref, []string{storage.FlagSeen, storage.FlagFlagged}); err != nil {
		t.Fatalf("UpdateFlags: %v", err)
	}

	metas, err := b.List(ctx, "example.com", "INBOX")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 1 || len(metas[0].Flags) != 2 {
		t.Fatalf("unexpected flags: %+v", metas)
	}
}

func TestUpdateFlagsUnknownRefErrors(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()
	err := b.UpdateFlags(ctx, storage.MessageRef{Vhost: "example.com", Mailbox: "INBOX", Key: "does-not-exist"}, nil)
	if err == nil {
		t.Fatal("expected error updating flags on an unknown ref")
	}
}

func TestDelete(t *testing.T) {
	b := newBackend(t)
	ctx := context.Background()

	ref, err := b.Write(ctx, "example.com", "INBOX", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := b.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Read(ctx, ref); err == nil {
		t.Fatal("expected Read to fail after Delete")
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
	b := newBackend(t)
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
