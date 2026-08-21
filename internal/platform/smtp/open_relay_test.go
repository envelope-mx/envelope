package smtp_test

import (
	"testing"

	gosmtp "github.com/emersion/go-smtp"

	envsmtp "github.com/envelope-mx/envelope/internal/platform/smtp"
)

// TestOpenRelayAudit is NFR-SEC-7's CI-checked audit: "verify the
// platform cannot be used as an open relay under any Directory
// misconfiguration... as part of CI, not solely manual review." Each
// sub-test is a named checklist item; the underlying behavior each one
// exercises already has its own dedicated test elsewhere in this package
// (TestInboundRejectsUnknownDomain, TestSubmissionRefusesUnauthenticated),
// but this consolidates them under one clearly-labeled suite so "did we
// check for open-relay behavior" has one obvious place to look, per
// release, rather than being implied by scattered protocol tests.
func TestOpenRelayAudit(t *testing.T) {
	t.Run("inbound rejects relaying to a domain we don't host", func(t *testing.T) {
		dir, store, q := newTestDeps(t)
		addr := startSMTP(t, envsmtp.Config{
			Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
			Directory: dir, Store: store, Queue: q, Filter: acceptAllFilter(),
		})

		c, err := gosmtp.Dial(addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer c.Close()

		if err := c.Mail("anyone@anywhere.test", nil); err != nil {
			t.Fatalf("Mail: %v", err)
		}
		// A third party attempting to relay through us to a domain we
		// don't host — the open-relay attempt — must be rejected before
		// DATA, permanently, with no way to submit a body at all.
		err = c.Rcpt("victim@not-our-domain.test", nil)
		if err == nil {
			t.Fatal("expected relaying to an unhosted domain to be rejected")
		}
		var smtpErr *gosmtp.SMTPError
		if !isSMTPError(err, &smtpErr) || smtpErr.Code != 550 {
			t.Fatalf("expected a permanent 550 rejection, got %v", err)
		}
	})

	t.Run("inbound still accepts genuine mail for a hosted domain", func(t *testing.T) {
		// The relay check must be domain-scoped, not a blanket "reject
		// everything unauthenticated" — inbound mail for our own tenants
		// is supposed to arrive with no authentication (FR-2.1/2.2).
		dir, store, q := newTestDeps(t)
		addr := startSMTP(t, envsmtp.Config{
			Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
			Directory: dir, Store: store, Queue: q, Filter: acceptAllFilter(),
		})

		c, err := gosmtp.Dial(addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer c.Close()

		if err := c.Mail("anyone@anywhere.test", nil); err != nil {
			t.Fatalf("Mail: %v", err)
		}
		if err := c.Rcpt("alice@example.test", nil); err != nil {
			t.Fatalf("expected mail for a hosted domain to be accepted, got %v", err)
		}
	})

	t.Run("submission refuses to relay for an unauthenticated sender", func(t *testing.T) {
		dir, store, q := newTestDeps(t)
		addr := startSMTP(t, envsmtp.Config{
			Mode: envsmtp.ModeSubmission, Name: "test-submission", Domain: "mx.example.test",
			AllowInsecureAuth: true,
			Directory:         dir, Store: store, Queue: q,
		})

		c, err := gosmtp.Dial(addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer c.Close()

		// No Auth call at all — an anonymous connection trying to use
		// submission as a relay to an arbitrary external recipient.
		err = c.Mail("anyone@anywhere.test", nil)
		if err == nil {
			t.Fatal("expected unauthenticated submission to be refused")
		}
		var smtpErr *gosmtp.SMTPError
		if !isSMTPError(err, &smtpErr) || smtpErr.Code != 530 {
			t.Fatalf("expected a 530 SMTPError, got %v", err)
		}
	})
}
