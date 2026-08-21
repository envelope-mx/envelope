package smtp_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/filter"
	"github.com/isaiahiroko/envelope/internal/filter/rspamd"
	"github.com/isaiahiroko/envelope/internal/metrics"
	envsmtp "github.com/isaiahiroko/envelope/internal/platform/smtp"
	"github.com/isaiahiroko/envelope/internal/storage"
)

// scoredRspamd reports a fixed score (or an error, simulating an outage).
type scoredRspamd struct {
	score float64
	err   error
}

func (s scoredRspamd) Check(context.Context, string, []string, io.Reader) (*rspamd.Verdict, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &rspamd.Verdict{Score: s.score}, nil
}

const testMsg = "From: sender@elsewhere.test\r\nTo: alice@example.test\r\nSubject: hi\r\n\r\nbody\r\n"

func TestInboundQuarantinesHighSpamScore(t *testing.T) {
	dir, store, q := newTestDeps(t)
	v, _ := dir.AddVhost("example.test")
	v.SpamRejectThreshold = 15
	v.SpamQuarantineThreshold = 6

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q,
		Filter: &filter.Pipeline{Resolver: noRecordResolver{}, Rspamd: scoredRspamd{score: 8}},
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(testMsg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	assertMailboxCount(t, store, "example.test", directory.MailboxPath("alice", "Quarantine"), 1)
	assertMailboxCount(t, store, "example.test", directory.MailboxPath("alice", "INBOX"), 0)
}

func TestInboundRejectsHighSpamScore(t *testing.T) {
	dir, store, q := newTestDeps(t)
	v, _ := dir.AddVhost("example.test")
	v.SpamRejectThreshold = 15
	v.SpamQuarantineThreshold = 6

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q,
		Filter: &filter.Pipeline{Resolver: noRecordResolver{}, Rspamd: scoredRspamd{score: 20}},
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	err = c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(testMsg))
	if err == nil {
		t.Fatal("expected a high spam score to reject the message")
	}
	var smtpErr *gosmtp.SMTPError
	if !isSMTPError(err, &smtpErr) || smtpErr.Code != 550 {
		t.Fatalf("expected a 550 SMTPError, got %v", err)
	}

	assertMailboxCount(t, store, "example.test", directory.MailboxPath("alice", "INBOX"), 0)
	assertMailboxCount(t, store, "example.test", directory.MailboxPath("alice", "Quarantine"), 0)
}

func TestInboundFailsOpenOnRspamdOutage(t *testing.T) {
	dir, store, q := newTestDeps(t)
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	before := testutil.ToFloat64(metrics.SpamScorerUnavailableTotal)

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q,
		Filter: &filter.Pipeline{Resolver: noRecordResolver{}, Rspamd: scoredRspamd{err: errors.New("connection refused")}},
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	// FR-2.6: an rspamd outage must not block mail — SendMail must succeed.
	if err := c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(testMsg)); err != nil {
		t.Fatalf("expected mail to still be accepted during an rspamd outage, got %v", err)
	}

	after := testutil.ToFloat64(metrics.SpamScorerUnavailableTotal)
	if after != before+1 {
		t.Fatalf("envelope_spam_scorer_unavailable_total = %v, want %v", after, before+1)
	}
	assertMailboxCount(t, store, "example.test", directory.MailboxPath("alice", "Quarantine"), 1)
}

func TestInboundRejectsOversizedMessageMidTransfer(t *testing.T) {
	dir, store, q := newTestDeps(t)
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q,
		Filter:          acceptAllFilter(),
		MaxMessageBytes: 64, // smaller than testMsg
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	err = c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(testMsg))
	if err == nil {
		t.Fatal("expected an oversized message to be rejected")
	}
	var smtpErr *gosmtp.SMTPError
	if !isSMTPError(err, &smtpErr) || smtpErr.Code != 552 {
		t.Fatalf("expected a 552 SMTPError, got %v", err)
	}

	assertMailboxCount(t, store, "example.test", directory.MailboxPath("alice", "INBOX"), 0)
}

func TestInboundPerVhostSizeLimitBelowServerCeiling(t *testing.T) {
	dir, store, q := newTestDeps(t)
	v, _ := dir.AddVhost("example.test")
	v.MaxMessageBytes = 16 // far below testMsg's length and the server default

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q, Filter: acceptAllFilter(),
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	err = c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(testMsg))
	if err == nil {
		t.Fatal("expected the recipient vhost's smaller FR-1.2 size limit to reject the message")
	}
	var smtpErr *gosmtp.SMTPError
	if !isSMTPError(err, &smtpErr) || smtpErr.Code != 552 {
		t.Fatalf("expected a 552 SMTPError, got %v", err)
	}
}

type fakeRateLimiter struct {
	allow bool
}

func (f fakeRateLimiter) Allow(context.Context, string, float64, float64) (bool, error) {
	return f.allow, nil
}

func TestInboundRateLimitsPerIP(t *testing.T) {
	dir, store, q := newTestDeps(t)
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q, Filter: acceptAllFilter(),
		RateLimiter:         fakeRateLimiter{allow: false},
		RateLimitIPCapacity: 1, RateLimitIPRefillPerSecond: 1,
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	err = c.Mail("sender@elsewhere.test", nil)
	if err == nil {
		t.Fatal("expected Mail to be rate-limited")
	}
	var smtpErr *gosmtp.SMTPError
	if !isSMTPError(err, &smtpErr) || smtpErr.Code != 450 {
		t.Fatalf("expected a 450 SMTPError, got %v", err)
	}
}

func assertMailboxCount(t *testing.T, store storage.Store, vhost, mailbox string, want int) {
	t.Helper()
	metas, err := store.List(context.Background(), vhost, mailbox)
	if err != nil {
		t.Fatalf("List(%s/%s): %v", vhost, mailbox, err)
	}
	if len(metas) != want {
		t.Fatalf("List(%s/%s) = %d messages, want %d", vhost, mailbox, len(metas), want)
	}
}
