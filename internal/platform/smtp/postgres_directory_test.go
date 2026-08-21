package smtp_test

import (
	"bytes"
	"fmt"
	"testing"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/dbtest"
	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/kms"
	envsmtp "github.com/isaiahiroko/envelope/internal/platform/smtp"
	"github.com/isaiahiroko/envelope/internal/queue"
	"github.com/isaiahiroko/envelope/internal/storage/maildir"
)

// TestInboundRejectsDeactivatedVhostPostgres is the FR-1.4 test against
// the real production Directory wiring (*directory.Service, Postgres),
// not the Phase 2 memory.Directory stand-in the rest of this package's
// tests use: RCPT TO must be rejected the moment a vhost is deactivated,
// with no caching/propagation delay, because inboundSession.Rcpt queries
// the Directory live on every call.
//
// This does not truncate vhosts/mailboxes/dkim_keys: those tables are
// shared with internal/directory's and internal/api's own tests against
// the same database, which go test runs concurrently as separate package
// binaries — see internal/directory/service_test.go's newService. A
// unique-per-run domain keeps this test isolated instead.
func TestInboundRejectsDeactivatedVhostPostgres(t *testing.T) {
	db := dbtest.DB(t)
	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	enc, err := kms.NewAESGCMEncryptor(bytes.Repeat([]byte("k"), kms.KeySize))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	dir := directory.New(db, enc)

	domain := fmt.Sprintf("deactivate-me-%s.test", uuid.NewString())
	ctx := t.Context()
	acct, err := dir.CreateAccount(ctx, "acct-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	v, err := dir.CreateVhost(ctx, acct.ID, domain)
	if err != nil {
		t.Fatalf("CreateVhost: %v", err)
	}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: maildir.New(t.TempDir()), Queue: queue.NewMemoryBackend(),
	})

	// Active: RCPT TO succeeds.
	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := c.Mail("sender@elsewhere.test", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	if err := c.Rcpt("alice@"+domain, nil); err != nil {
		t.Fatalf("expected Rcpt to an active vhost to succeed, got %v", err)
	}
	c.Close()

	if err := dir.DeactivateVhost(ctx, v.ID); err != nil {
		t.Fatalf("DeactivateVhost: %v", err)
	}

	// Deactivated: RCPT TO now rejected with a permanent 550 (FR-1.4/FR-2.2),
	// on a brand new connection so there's no per-connection caching to
	// mask a slow propagation.
	c2, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c2.Close()
	if err := c2.Mail("sender@elsewhere.test", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	err = c2.Rcpt("alice@"+domain, nil)
	if err == nil {
		t.Fatal("expected Rcpt to a deactivated vhost to fail")
	}
	var smtpErr *gosmtp.SMTPError
	if !isSMTPError(err, &smtpErr) || smtpErr.Code != 550 {
		t.Fatalf("expected a 550 SMTPError, got %v", err)
	}
}
