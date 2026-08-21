package api_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"strings"
	"testing"

	"github.com/awesome-goose/goose"
	"github.com/awesome-goose/goose/core"
	"github.com/awesome-goose/goose/platforms/api"
	"github.com/awesome-goose/goose/types"
	"github.com/google/uuid"

	envapi "github.com/envelope-mx/envelope/internal/api"
	"github.com/envelope-mx/envelope/internal/apiauth"
	"github.com/envelope-mx/envelope/internal/app"
	"github.com/envelope-mx/envelope/internal/audit"
	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/queue"
	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/storage/maildir"
	"github.com/envelope-mx/envelope/internal/webhook"
)

// startAPIForMessageTest is startAPIWithWebhooks plus returning the
// storage.Store, queue.Backend, and webhook.EventQueue the API instance
// was actually wired to, so the send-endpoint tests can inspect what got
// staged/enqueued/dispatched — every other test in this file doesn't need
// that access, so this duplicates a little of startAPIWithWebhooks's body
// rather than complicating that shared helper's signature for one caller
// (see startAPIForDataTest's identical reasoning). quota may be nil (no
// quota enforcement, the common case).
func startAPIForMessageTest(t *testing.T, svc *directory.Service, quota *envapi.QuotaPolicy) (base, adminToken string, msgStore storage.Store, q queue.Backend, events webhook.EventQueue) {
	t.Helper()

	port := reservePort(t)
	admin := "env_test_admin_" + uuid.NewString()
	store := maildir.New(t.TempDir())
	webhookStore := webhook.NewMemoryStore()
	backend := queue.NewMemoryBackend()
	eventQueue := webhook.NewMemoryEventQueue()
	dispatcher := webhook.NewDispatcher(webhookStore, eventQueue)
	platform := api.NewPlatform(api.WithName("test-api"), api.WithHost("127.0.0.1"), api.WithPort(port))
	initializers := []func(types.Container) error{
		func(c types.Container) error {
			return c.Register(func() *directory.Service { return svc }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() storage.Store { return store }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() webhook.Store { return webhookStore }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() apiauth.Store { return apiauth.NewMemoryStore() }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() audit.Store { return audit.NewMemoryStore() }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() *envapi.AdminToken { return &envapi.AdminToken{Value: admin} }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() queue.Backend { return backend }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() webhook.Enqueuer { return dispatcher }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() *envapi.QuotaPolicy { return quota }, "", true)
		},
	}

	go func() {
		_, _ = core.NewKernel().Start(goose.API(platform, &app.AppModule{}, initializers))
	}()

	addr := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitReady(t, addr+"/health")
	return addr, admin, store, backend, eventQueue
}

// TestCreateAccountAutoIssuesToken covers the account-creation entry point
// every self-serve flow starts from: CreateAccount is admin-gated but
// mints the account's first token in the same response, and that token
// immediately authorizes account-scoped requests with no further admin
// involvement.
func TestCreateAccountAutoIssuesToken(t *testing.T) {
	svc := newService(t)
	base, admin := startAPI(t, svc)

	status, resp := doJSON(t, http.MethodPost, base+"/accounts", admin, map[string]any{"name": "Acme Inc"})
	if status != http.StatusCreated {
		t.Fatalf("create account: status=%d body=%v", status, resp)
	}
	data := resp["data"].(map[string]any)
	account := data["account"].(map[string]any)
	tok := data["token"].(map[string]any)
	if account["id"] == "" || account["name"] != "Acme Inc" {
		t.Fatalf("unexpected account in response: %+v", account)
	}
	accountID := account["id"].(string)
	if tok["token"] == "" || tok["accountId"] != accountID {
		t.Fatalf("unexpected auto-issued token in response: %+v", tok)
	}
	rawToken := tok["token"].(string)

	// The freshly issued token immediately authorizes account-scoped
	// requests — no separate admin-driven token-mint step needed.
	status, _ = doJSON(t, http.MethodGet, base+"/accounts/"+accountID, rawToken, nil)
	if status != http.StatusOK {
		t.Fatalf("expected the auto-issued token to authorize GET /accounts/%s, got %d", accountID, status)
	}

	// A non-admin token cannot create further accounts (platform-level).
	status, _ = doJSON(t, http.MethodPost, base+"/accounts", rawToken, map[string]any{"name": "should-fail"})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin token creating an account, got %d", status)
	}
}

// TestSendMessageHappyPath exercises the REST send endpoint end to end:
// authenticated with an account-scoped token, a multi-recipient,
// text+html+attachment message is composed, DKIM-signed, staged, and
// enqueued once per recipient — exactly the shape SMTP submission already
// produces, so the deliverer needs no changes to pick it up.
func TestSendMessageHappyPath(t *testing.T) {
	svc := newService(t)
	base, admin, msgStore, q, events := startAPIForMessageTest(t, svc, nil)
	accountID, token := createAccount(t, base, admin)
	domain := t.Name() + "-" + uuid.NewString() + ".test"
	vhostID := createVhost(t, base, token, accountID, domain)

	// A subscription to message.queued, so this test can also confirm the
	// event actually fires (once, not once per recipient).
	status, _ := doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/webhooks", token,
		map[string]any{"url": "https://example.test/hook", "secret": "s3cret", "eventTypes": []string{"message.queued"}})
	if status != http.StatusCreated {
		t.Fatalf("create webhook subscription: status=%d", status)
	}

	from := "Alice <sender@" + domain + ">"
	status, resp := doJSON(t, http.MethodPost, base+"/accounts/"+accountID+"/messages", token, map[string]any{
		"from":    from,
		"to":      []string{"rcpt1@example.test", "rcpt2@example.test"},
		"cc":      []string{"cc@example.test"},
		"subject": "Hello",
		"text":    "hello in plain text",
		"html":    "<p>hello in html</p>",
		"attachments": []map[string]any{
			{"filename": "note.txt", "contentType": "text/plain", "contentBase64": base64.StdEncoding.EncodeToString([]byte("attachment body"))},
		},
		"headers": map[string]string{"X-Test-Header": "yes"},
	})
	if status != http.StatusCreated {
		t.Fatalf("send message: status=%d body=%v", status, resp)
	}
	data := resp["data"].(map[string]any)
	if data["queued"] != float64(3) { // to (2) + cc (1), bcc empty
		t.Fatalf("expected queued=3, got %+v", data)
	}
	jobIDs, _ := data["jobIds"].([]any)
	if len(jobIDs) != 3 {
		t.Fatalf("expected 3 jobIds, got %+v", jobIDs)
	}

	// Drain the queue and inspect every job.
	ctx := context.Background()
	seenTo := make(map[string]bool)
	var bodyRef string
	for i := 0; i < 3; i++ {
		job, ok, err := q.Dequeue(ctx)
		if err != nil || !ok {
			t.Fatalf("Dequeue %d: ok=%v err=%v", i, ok, err)
		}
		if job.Vhost != domain {
			t.Fatalf("expected job.Vhost=%q, got %q", domain, job.Vhost)
		}
		if job.From != "sender@"+domain {
			t.Fatalf("expected job.From to be the bare address (no display name), got %q", job.From)
		}
		seenTo[job.To] = true
		bodyRef = job.BodyRef
	}
	for _, want := range []string{"rcpt1@example.test", "rcpt2@example.test", "cc@example.test"} {
		if !seenTo[want] {
			t.Fatalf("expected a queued job to %q, got %+v", want, seenTo)
		}
	}

	// Read the staged, signed body back and sanity-check its MIME
	// structure via the standard library's own parser, not just this
	// package's own composer agreeing with itself.
	rc, err := msgStore.Read(ctx, storage.MessageRef{Vhost: domain, Mailbox: storage.OutboxMailbox, Key: bodyRef})
	if err != nil {
		t.Fatalf("Read staged body: %v", err)
	}
	defer rc.Close()
	msg, err := mail.ReadMessage(rc)
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	if got := msg.Header.Get("From"); got != from {
		t.Fatalf("expected From header %q, got %q", from, got)
	}
	if msg.Header.Get("Subject") != "Hello" {
		t.Fatalf("expected Subject header, got %q", msg.Header.Get("Subject"))
	}
	if msg.Header.Get("X-Test-Header") != "yes" {
		t.Fatalf("expected custom header to survive composition, got %q", msg.Header.Get("X-Test-Header"))
	}
	if msg.Header.Get("Dkim-Signature") == "" {
		t.Fatal("expected the staged body to already be DKIM-signed")
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type: %v", err)
	}
	if !strings.HasPrefix(mediaType, "multipart/mixed") {
		t.Fatalf("expected a multipart/mixed top level (attachment present), got %q", mediaType)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var partCount int
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		partCount++
		part.Close()
	}
	if partCount != 2 { // the alternative(text+html) body part, plus the one attachment
		t.Fatalf("expected 2 top-level mixed parts (body + attachment), got %d", partCount)
	}

	// message.queued fired exactly once (not once per recipient).
	job, ok, err := events.Dequeue(ctx)
	if err != nil || !ok {
		t.Fatalf("expected a message.queued delivery job: ok=%v err=%v", ok, err)
	}
	if job.EventType != webhook.EventMessageQueued {
		t.Fatalf("expected event type %q, got %q", webhook.EventMessageQueued, job.EventType)
	}
	if _, ok, _ := events.Dequeue(ctx); ok {
		t.Fatal("expected exactly one message.queued event, found a second")
	}
}

// TestSendMessageRejectsWrongAccountFrom covers ownership: a caller
// authenticated for one account cannot send from an address whose vhost
// belongs to a different account, even though the bearer token itself is
// otherwise perfectly valid.
func TestSendMessageRejectsWrongAccountFrom(t *testing.T) {
	svc := newService(t)
	base, admin, _, _, _ := startAPIForMessageTest(t, svc, nil)
	accountA, tokenA := createAccount(t, base, admin)
	accountB, tokenB := createAccount(t, base, admin)
	domainA := t.Name() + "-a-" + uuid.NewString() + ".test"
	createVhost(t, base, tokenA, accountA, domainA)

	status, resp := doJSON(t, http.MethodPost, base+"/accounts/"+accountB+"/messages", tokenB, map[string]any{
		"from": "sender@" + domainA, "to": []string{"rcpt@example.test"}, "subject": "x", "text": "x",
	})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 sending from a vhost owned by a different account, got %d body=%v", status, resp)
	}
}

// TestSendMessageQuotaExceeded covers FR-3.7 enforced through the REST
// path, the same way internal/platform/smtp/submission.go's checkQuota
// already does for SMTP submission.
func TestSendMessageQuotaExceeded(t *testing.T) {
	svc := newService(t)
	limiter := newCountingLimiter(0) // exhausted from the first call
	base, admin, _, _, _ := startAPIForMessageTest(t, svc, &envapi.QuotaPolicy{Limiter: limiter})
	accountID, token := createAccount(t, base, admin)
	domain := t.Name() + "-" + uuid.NewString() + ".test"
	vhostID := createVhost(t, base, token, accountID, domain)

	status, _ := doJSON(t, http.MethodPatch, base+"/vhosts/"+vhostID+"/policy", token,
		map[string]any{"dailyQuota": 10})
	if status != http.StatusOK {
		t.Fatalf("set daily quota: status=%d", status)
	}

	status, resp := doJSON(t, http.MethodPost, base+"/accounts/"+accountID+"/messages", token, map[string]any{
		"from": "sender@" + domain, "to": []string{"rcpt@example.test"}, "subject": "x", "text": "x",
	})
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once the daily quota is exhausted, got %d body=%v", status, resp)
	}
}

// TestSendMessageValidation covers the request-shape rejections that never
// reach quota/DKIM/enqueue at all.
func TestSendMessageValidation(t *testing.T) {
	svc := newService(t)
	base, admin, _, _, _ := startAPIForMessageTest(t, svc, nil)
	accountID, token := createAccount(t, base, admin)
	domain := t.Name() + "-" + uuid.NewString() + ".test"
	createVhost(t, base, token, accountID, domain)
	from := "sender@" + domain

	cases := []struct {
		name string
		body map[string]any
	}{
		{"no recipients", map[string]any{"from": from, "subject": "x", "text": "x"}},
		{"no text or html", map[string]any{"from": from, "to": []string{"rcpt@example.test"}, "subject": "x"}},
		{"malformed from", map[string]any{"from": "not-an-address", "to": []string{"rcpt@example.test"}, "text": "x"}},
		{"malformed attachment base64", map[string]any{
			"from": from, "to": []string{"rcpt@example.test"}, "text": "x",
			"attachments": []map[string]any{{"filename": "a.txt", "contentBase64": "not-valid-base64!!"}},
		}},
		{"reserved header override", map[string]any{
			"from": from, "to": []string{"rcpt@example.test"}, "text": "x",
			"headers": map[string]string{"Content-Type": "text/evil"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, resp := doJSON(t, http.MethodPost, base+"/accounts/"+accountID+"/messages", token, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%v", status, resp)
			}
		})
	}
}
