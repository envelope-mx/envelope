package smtp_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	gosasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/envelope-mx/envelope/internal/filter"
	envsmtp "github.com/envelope-mx/envelope/internal/platform/smtp"
	"github.com/envelope-mx/envelope/internal/webhook"
)

// fakeEnqueuer records every webhook.Enqueuer.Enqueue call, standing in
// for a real webhook.Dispatcher so these tests can assert on what would
// have been scheduled for delivery without needing an HTTP endpoint.
type fakeEnqueuer struct {
	mu     sync.Mutex
	events []enqueuedEvent
}

type enqueuedEvent struct {
	Vhost, EventType string
	Payload          []byte
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, vhost, eventType string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, enqueuedEvent{vhost, eventType, payload})
	return nil
}

func (f *fakeEnqueuer) all() []enqueuedEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]enqueuedEvent{}, f.events...)
}

var _ webhook.Enqueuer = (*fakeEnqueuer)(nil)

func TestInboundFiresMessageReceivedOnAccept(t *testing.T) {
	dir, store, q := newTestDeps(t)
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	hooks := &fakeEnqueuer{}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q, Filter: acceptAllFilter(), Webhooks: hooks,
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(testMsg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	events := hooks.all()
	if len(events) != 1 || events[0].EventType != webhook.EventMessageReceived || events[0].Vhost != "example.test" {
		t.Fatalf("expected exactly one message.received event for example.test, got %+v", events)
	}
	assertQuarantineField(t, events[0].Payload, false)
}

func TestInboundFiresMessageReceivedOnQuarantineWithFlag(t *testing.T) {
	dir, store, q := newTestDeps(t)
	v, _ := dir.AddVhost("example.test")
	v.SpamRejectThreshold = 15
	v.SpamQuarantineThreshold = 6
	hooks := &fakeEnqueuer{}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q, Webhooks: hooks,
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

	events := hooks.all()
	if len(events) != 1 || events[0].EventType != webhook.EventMessageReceived {
		t.Fatalf("expected exactly one message.received event, got %+v", events)
	}
	assertQuarantineField(t, events[0].Payload, true)
}

func TestInboundRejectDoesNotFireWebhook(t *testing.T) {
	dir, store, q := newTestDeps(t)
	v, _ := dir.AddVhost("example.test")
	v.SpamRejectThreshold = 15
	v.SpamQuarantineThreshold = 6
	hooks := &fakeEnqueuer{}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q, Webhooks: hooks,
		Filter: &filter.Pipeline{Resolver: noRecordResolver{}, Rspamd: scoredRspamd{score: 20}},
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(testMsg)); err == nil {
		t.Fatal("expected the message to be rejected")
	}

	if events := hooks.all(); len(events) != 0 {
		t.Fatalf("expected no webhook events fired for a rejected message, got %+v", events)
	}
}

func assertQuarantineField(t *testing.T, payload []byte, want bool) {
	t.Helper()
	var envelope struct {
		Data struct {
			Quarantine bool `json:"quarantine"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("unmarshal payload: %v (payload: %s)", err, payload)
	}
	if envelope.Data.Quarantine != want {
		t.Fatalf("payload quarantine = %v, want %v (payload: %s)", envelope.Data.Quarantine, want, payload)
	}
}

// TestSubmissionFiresMessageQueuedOnce covers submission.go's fireQueued:
// a successful authenticated submission fires message.queued exactly once
// (not once per recipient), distinct from the deliverer's later
// per-recipient delivered/bounced/deferred events.
func TestSubmissionFiresMessageQueuedOnce(t *testing.T) {
	dir, store, q := newTestDeps(t)
	hooks := &fakeEnqueuer{}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeSubmission, Name: "test-submission", Domain: "mx.example.test",
		AllowInsecureAuth: true,
		Directory:         dir, Store: store, Queue: q, Webhooks: hooks,
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.Auth(gosasl.NewPlainClient("", "alice@example.test", "s3cret")); err != nil {
		t.Fatalf("Auth: %v", err)
	}
	if err := c.SendMail("alice@example.test", []string{"bob@remote.test", "carol@remote.test"}, strings.NewReader(testMsg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	events := hooks.all()
	if len(events) != 1 || events[0].EventType != webhook.EventMessageQueued || events[0].Vhost != "example.test" {
		t.Fatalf("expected exactly one message.queued event for example.test, got %+v", events)
	}
}

func TestSubmissionQuotaExceededRejects(t *testing.T) {
	dir, store, q := newTestDeps(t)
	v, _ := dir.AddVhost("example.test")
	v.DailyQuota = 1

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeSubmission, Name: "test-submission", Domain: "mx.example.test",
		AllowInsecureAuth: true,
		Directory:         dir, Store: store, Queue: q,
		Quota: fakeRateLimiter{allow: false},
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.Auth(gosasl.NewPlainClient("", "alice@example.test", "s3cret")); err != nil {
		t.Fatalf("Auth: %v", err)
	}

	err = c.SendMail("alice@example.test", []string{"bob@remote.test"}, strings.NewReader(testMsg))
	if err == nil {
		t.Fatal("expected the daily quota to reject submission")
	}
	var smtpErr *gosmtp.SMTPError
	if !isSMTPError(err, &smtpErr) || smtpErr.Code != 452 {
		t.Fatalf("expected a 452 SMTPError, got %v", err)
	}
}

func TestSubmissionUnconfiguredQuotaIsNotEnforced(t *testing.T) {
	dir, store, q := newTestDeps(t)
	// DailyQuota left at its zero value ("unconfigured") even though the
	// Quota checker below would reject every call if consulted.
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if err := dir.AddAccount("example.test", "alice", "s3cret"); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeSubmission, Name: "test-submission", Domain: "mx.example.test",
		AllowInsecureAuth: true,
		Directory:         dir, Store: store, Queue: q,
		Quota: fakeRateLimiter{allow: false},
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.Auth(gosasl.NewPlainClient("", "alice@example.test", "s3cret")); err != nil {
		t.Fatalf("Auth: %v", err)
	}

	if err := c.SendMail("alice@example.test", []string{"bob@remote.test"}, strings.NewReader(testMsg)); err != nil {
		t.Fatalf("expected submission to succeed with no DailyQuota configured, got %v", err)
	}
}
