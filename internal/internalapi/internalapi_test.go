package internalapi_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/isaiahiroko/envelope/internal/directory/memory"
	"github.com/isaiahiroko/envelope/internal/internalapi"
	"github.com/isaiahiroko/envelope/internal/queue"
	"github.com/isaiahiroko/envelope/internal/storage"
	"github.com/isaiahiroko/envelope/internal/storage/maildir"
)

// fakeRateLimiter records every call and returns a canned answer — a real
// internal/ratelimit.PostgresLimiter needs Postgres, which this package's
// tests don't otherwise depend on.
type fakeRateLimiter struct {
	mu      sync.Mutex
	allowed bool
	calls   []string // "key:capacity:refill"
}

func (f *fakeRateLimiter) Allow(_ context.Context, key string, capacity, refillPerSecond float64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("%s:%v:%v", key, capacity, refillPerSecond))
	return f.allowed, nil
}

// fakeEnqueuer records every webhook.Enqueuer call.
type fakeEnqueuer struct {
	mu      sync.Mutex
	calls   int
	vhost   string
	event   string
	payload []byte
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, vhost, eventType string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.vhost, f.event, f.payload = vhost, eventType, payload
	return nil
}

const (
	inboundToken    = "test-token-smtp-inbound"
	submissionToken = "test-token-smtp-submission"
	imapToken       = "test-token-imap"
)

type testEnv struct {
	url     string
	dir     *memory.Directory
	store   storage.Store
	q       *queue.MemoryBackend
	limiter *fakeRateLimiter
	hooks   *fakeEnqueuer
}

func newTestServer(t *testing.T) *testEnv {
	t.Helper()
	dir := memory.New()
	store := maildir.New(t.TempDir())
	q := queue.NewMemoryBackend()
	limiter := &fakeRateLimiter{allowed: true}
	hooks := &fakeEnqueuer{}

	tokens := map[string]string{
		inboundToken:    internalapi.RoleSMTPInbound,
		submissionToken: internalapi.RoleSMTPSubmission,
		imapToken:       internalapi.RoleIMAP,
	}
	srv := internalapi.NewServer(dir, store, q, limiter, hooks, tokens)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	return &testEnv{url: httpSrv.URL, dir: dir, store: store, q: q, limiter: limiter, hooks: hooks}
}

func TestDirectoryClientVhostRoundTripsIncludingDKIMKey(t *testing.T) {
	env := newTestServer(t)
	v, err := env.dir.AddVhost("example.test")
	if err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	client := internalapi.NewDirectoryClient(env.url, inboundToken)
	got, ok := client.Vhost(context.Background(), "example.test")
	if !ok {
		t.Fatal("expected vhost to be found")
	}
	if got.ID != v.ID || got.Domain != v.Domain || !got.Active || got.DKIMSelector != v.DKIMSelector {
		t.Fatalf("unexpected vhost: %+v", got)
	}
	if got.DKIMKey == nil {
		t.Fatal("expected DKIM key to round-trip")
	}
	if got.DKIMKey.N.Cmp(v.DKIMKey.N) != 0 {
		t.Fatal("expected the same DKIM key material to round-trip through the internal API")
	}
}

func TestDirectoryClientVhostNotFound(t *testing.T) {
	env := newTestServer(t)
	client := internalapi.NewDirectoryClient(env.url, inboundToken)
	_, ok := client.Vhost(context.Background(), "does-not-exist.test")
	if ok {
		t.Fatal("expected an unregistered domain to be not found")
	}
}

func TestDirectoryClientVhostActiveDerivedFromVhost(t *testing.T) {
	env := newTestServer(t)
	if _, err := env.dir.AddVhost("active.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	client := internalapi.NewDirectoryClient(env.url, inboundToken)
	if !client.VhostActive(context.Background(), "active.test") {
		t.Fatal("expected active.test to be active")
	}
	if client.VhostActive(context.Background(), "unknown.test") {
		t.Fatal("expected an unregistered domain to be inactive")
	}
}

func TestDirectoryClientAuthenticate(t *testing.T) {
	env := newTestServer(t)
	if _, err := env.dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if err := env.dir.AddAccount("example.test", "alice", "s3cret"); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	client := internalapi.NewDirectoryClient(env.url, submissionToken)
	if !client.Authenticate(context.Background(), "example.test", "alice", "s3cret") {
		t.Fatal("expected correct credentials to authenticate")
	}
	if client.Authenticate(context.Background(), "example.test", "alice", "wrong") {
		t.Fatal("expected wrong password to fail")
	}
}

func TestStoreClientWriteAndRead(t *testing.T) {
	env := newTestServer(t)
	client := internalapi.NewStoreClient(env.url, inboundToken)

	ref, err := client.Write(context.Background(), "example.test", "INBOX", strings.NewReader("the body"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if ref.Vhost != "example.test" || ref.Mailbox != "INBOX" || ref.Key == "" {
		t.Fatalf("unexpected ref: %+v", ref)
	}

	readClient := internalapi.NewStoreClient(env.url, imapToken)
	rc, err := readClient.Read(context.Background(), ref)
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

func TestStoreClientList(t *testing.T) {
	env := newTestServer(t)
	writer := internalapi.NewStoreClient(env.url, inboundToken)
	if _, err := writer.Write(context.Background(), "example.test", "INBOX", strings.NewReader("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	lister := internalapi.NewStoreClient(env.url, imapToken)
	metas, err := lister.List(context.Background(), "example.test", "INBOX")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 1 || metas[0].Ref.Vhost != "example.test" || metas[0].Ref.Mailbox != "INBOX" {
		t.Fatalf("unexpected list result: %+v", metas)
	}
}

func TestStoreClientUpdateFlags(t *testing.T) {
	env := newTestServer(t)
	writer := internalapi.NewStoreClient(env.url, inboundToken)
	ref, err := writer.Write(context.Background(), "example.test", "INBOX", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	imapClient := internalapi.NewStoreClient(env.url, imapToken)
	if err := imapClient.UpdateFlags(context.Background(), ref, []string{storage.FlagSeen}); err != nil {
		t.Fatalf("UpdateFlags: %v", err)
	}

	metas, err := imapClient.List(context.Background(), "example.test", "INBOX")
	if err != nil || len(metas) != 1 || len(metas[0].Flags) != 1 {
		t.Fatalf("expected flag to be set: %+v (err %v)", metas, err)
	}
}

func TestStoreClientListVhostAndDeleteAreUnsupported(t *testing.T) {
	client := internalapi.NewStoreClient(newTestServer(t).url, imapToken)
	if _, err := client.ListVhost(context.Background(), "example.test"); err == nil {
		t.Fatal("expected ListVhost to be unsupported over the internal API")
	}
	if err := client.Delete(context.Background(), storage.MessageRef{Vhost: "example.test", Mailbox: "INBOX", Key: "x"}); err == nil {
		t.Fatal("expected Delete to be unsupported over the internal API")
	}
}

func TestQueueClientEnqueue(t *testing.T) {
	env := newTestServer(t)
	client := internalapi.NewQueueClient(env.url, submissionToken)

	job := queue.Job{ID: "job-1", Vhost: "example.test", From: "a@example.test", To: "b@other.test", BodyRef: "ref-1", NextAttemptAt: time.Now()}
	if err := client.Enqueue(context.Background(), job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	count, err := env.q.Count(context.Background())
	if err != nil || count != 1 {
		t.Fatalf("expected 1 job enqueued on the real backend, got count=%d err=%v", count, err)
	}
}

func TestQueueClientOtherMethodsAreUnsupported(t *testing.T) {
	client := internalapi.NewQueueClient(newTestServer(t).url, submissionToken)
	if _, _, err := client.Dequeue(context.Background()); err == nil {
		t.Fatal("expected Dequeue to be unsupported over the internal API")
	}
	if err := client.Complete(context.Background(), "job-1"); err == nil {
		t.Fatal("expected Complete to be unsupported over the internal API")
	}
	if err := client.Fail(context.Background(), "job-1", nil, time.Now()); err == nil {
		t.Fatal("expected Fail to be unsupported over the internal API")
	}
	if _, err := client.Count(context.Background()); err == nil {
		t.Fatal("expected Count to be unsupported over the internal API")
	}
}

func TestRateLimiterClientAllow(t *testing.T) {
	env := newTestServer(t)
	env.limiter.allowed = true
	client := internalapi.NewRateLimiterClient(env.url, inboundToken)

	allowed, err := client.Allow(context.Background(), "ip:1.2.3.4", 20, 1)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed=true")
	}

	env.limiter.allowed = false
	allowed, err = client.Allow(context.Background(), "ip:1.2.3.4", 20, 1)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if allowed {
		t.Fatal("expected allowed=false")
	}

	env.limiter.mu.Lock()
	defer env.limiter.mu.Unlock()
	if len(env.limiter.calls) != 2 {
		t.Fatalf("expected 2 calls to reach the real limiter, got %v", env.limiter.calls)
	}
}

func TestWebhookClientEnqueue(t *testing.T) {
	env := newTestServer(t)
	client := internalapi.NewWebhookClient(env.url, inboundToken)

	if err := client.Enqueue(context.Background(), "example.test", "message.received", []byte(`{"a":1}`)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	env.hooks.mu.Lock()
	defer env.hooks.mu.Unlock()
	if env.hooks.calls != 1 || env.hooks.vhost != "example.test" || env.hooks.event != "message.received" {
		t.Fatalf("unexpected call recorded: %+v", env.hooks)
	}
	if string(env.hooks.payload) != `{"a":1}` {
		t.Fatalf("payload mismatch: %s", env.hooks.payload)
	}
}

// TestAuthorizationMatrix is this package's actual security property,
// verified directly: each role's token can reach exactly the scopes
// roleScopes grants it (see server.go) and is rejected (403) for every
// other scope — the HTTP-layer equivalent of proving
// deploy/postgres/roles.sql's GRANT statements actually restrict what a
// compromised credential could do.
func TestAuthorizationMatrix(t *testing.T) {
	env := newTestServer(t)
	if _, err := env.dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	type probe struct {
		scope string
		call  func(token string) error
	}
	probes := []probe{
		{internalapi.ScopeDirectoryVhost, func(token string) error {
			_, _ = internalapi.NewDirectoryClient(env.url, token).Vhost(context.Background(), "example.test")
			return nil // Directory.Vhost has no error return; scope is proven via handleVhost below instead
		}},
		{internalapi.ScopeDirectoryAuthenticate, func(token string) error {
			internalapi.NewDirectoryClient(env.url, token).Authenticate(context.Background(), "example.test", "x", "y")
			return nil
		}},
		{internalapi.ScopeStoreWrite, func(token string) error {
			_, err := internalapi.NewStoreClient(env.url, token).Write(context.Background(), "example.test", "INBOX", strings.NewReader("x"))
			return err
		}},
		{internalapi.ScopeStoreList, func(token string) error {
			_, err := internalapi.NewStoreClient(env.url, token).List(context.Background(), "example.test", "INBOX")
			return err
		}},
		{internalapi.ScopeQueueEnqueue, func(token string) error {
			return internalapi.NewQueueClient(env.url, token).Enqueue(context.Background(), queue.Job{ID: "probe", NextAttemptAt: time.Now()})
		}},
		{internalapi.ScopeRateLimitAllow, func(token string) error {
			_, err := internalapi.NewRateLimiterClient(env.url, token).Allow(context.Background(), "k", 1, 1)
			return err
		}},
		{internalapi.ScopeWebhookEnqueue, func(token string) error {
			return internalapi.NewWebhookClient(env.url, token).Enqueue(context.Background(), "example.test", "message.received", nil)
		}},
	}

	roleTokens := map[string]string{
		internalapi.RoleSMTPInbound:    inboundToken,
		internalapi.RoleSMTPSubmission: submissionToken,
		internalapi.RoleIMAP:           imapToken,
	}
	granted := map[string]map[string]bool{
		internalapi.RoleSMTPInbound: {
			internalapi.ScopeDirectoryVhost: true, internalapi.ScopeStoreWrite: true,
			internalapi.ScopeRateLimitAllow: true, internalapi.ScopeWebhookEnqueue: true,
		},
		internalapi.RoleSMTPSubmission: {
			internalapi.ScopeDirectoryVhost: true, internalapi.ScopeDirectoryAuthenticate: true,
			internalapi.ScopeStoreWrite: true, internalapi.ScopeQueueEnqueue: true, internalapi.ScopeRateLimitAllow: true,
		},
		internalapi.RoleIMAP: {
			internalapi.ScopeDirectoryAuthenticate: true, internalapi.ScopeStoreList: true,
		},
	}

	for role, token := range roleTokens {
		for _, p := range probes {
			// Directory.Vhost/Authenticate never surface an error to the
			// caller (see directory.Directory's own no-error-return
			// shape), so those two scopes are proven via a raw HTTP probe
			// instead of the fail-closed client wrapper.
			if p.scope == internalapi.ScopeDirectoryVhost || p.scope == internalapi.ScopeDirectoryAuthenticate {
				continue
			}
			err := p.call(token)
			shouldSucceed := granted[role][p.scope]
			if shouldSucceed && err != nil {
				t.Errorf("role %q, scope %q: expected success (granted), got error: %v", role, p.scope, err)
			}
			if !shouldSucceed && err == nil {
				t.Errorf("role %q, scope %q: expected rejection (not granted), got success", role, p.scope)
			}
		}
	}
}

// TestDirectoryScopesRejectUnauthorizedTokens covers what
// TestAuthorizationMatrix explicitly skips: directory.vhost and
// directory.authenticate never surface an error through DirectoryClient
// (matching directory.Directory's own no-error-return method shapes), so
// their 403 behavior has to be checked against the raw HTTP response
// instead of through the fail-closed client wrapper.
func TestDirectoryScopesRejectUnauthorizedTokens(t *testing.T) {
	env := newTestServer(t)
	hc := &http.Client{Timeout: 5 * time.Second}

	probe := func(t *testing.T, method, path, token string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, env.url+path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set(internalapi.HeaderToken, token)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// imap's token is granted directory.authenticate but not
	// directory.vhost (see the granted table in TestAuthorizationMatrix).
	if code := probe(t, http.MethodPost, "/internal/v1/directory/vhost", imapToken); code != http.StatusForbidden {
		t.Fatalf("imap token calling directory.vhost: expected 403, got %d", code)
	}
	if code := probe(t, http.MethodPost, "/internal/v1/directory/authenticate", imapToken); code != http.StatusOK {
		t.Fatalf("imap token calling directory.authenticate: expected 200, got %d", code)
	}

	// inbound's token is granted directory.vhost but not
	// directory.authenticate.
	if code := probe(t, http.MethodPost, "/internal/v1/directory/vhost", inboundToken); code != http.StatusOK {
		t.Fatalf("inbound token calling directory.vhost: expected 200, got %d", code)
	}
	if code := probe(t, http.MethodPost, "/internal/v1/directory/authenticate", inboundToken); code != http.StatusForbidden {
		t.Fatalf("inbound token calling directory.authenticate: expected 403, got %d", code)
	}
}

func TestUnknownTokenReturns401(t *testing.T) {
	env := newTestServer(t)
	client := internalapi.NewRateLimiterClient(env.url, "not-a-real-token")
	if _, err := client.Allow(context.Background(), "k", 1, 1); err == nil {
		t.Fatal("expected an unrecognized token to be rejected")
	}
}

func TestMissingTokenReturns401(t *testing.T) {
	env := newTestServer(t)
	client := internalapi.NewRateLimiterClient(env.url, "")
	if _, err := client.Allow(context.Background(), "k", 1, 1); err == nil {
		t.Fatal("expected a missing token to be rejected")
	}
}
