package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awesome-goose/goose"
	"github.com/awesome-goose/goose/core"
	"github.com/awesome-goose/goose/platforms/api"
	"github.com/awesome-goose/goose/types"
	"github.com/google/uuid"

	envapi "github.com/isaiahiroko/envelope/internal/api"
	"github.com/isaiahiroko/envelope/internal/apiauth"
	"github.com/isaiahiroko/envelope/internal/app"
	"github.com/isaiahiroko/envelope/internal/audit"
	"github.com/isaiahiroko/envelope/internal/dbtest"
	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/kms"
	"github.com/isaiahiroko/envelope/internal/queue"
	"github.com/isaiahiroko/envelope/internal/storage"
	"github.com/isaiahiroko/envelope/internal/storage/maildir"
	"github.com/isaiahiroko/envelope/internal/webhook"
)

// startAPI is a convenience wrapper for tests that don't care about
// webhooks specifically — it still needs a webhook.Store registered
// because WebhookController's inject:"" field is part of the same
// api.Module every instance boots (see internal/api/module.go), so an
// instance without one would fail to resolve its container and never
// come up. Returns the admin bearer token every authenticated test
// request needs (FR-5.2).
func startAPI(t *testing.T, svc *directory.Service) (base, adminToken string) {
	t.Helper()
	return startAPIWithWebhooks(t, svc, webhook.NewMemoryStore())
}

// startAPIWithRateLimit is startAPIWithWebhooks plus a registered
// *envapi.RateLimitPolicy — every other test in this file leaves
// RateLimitPolicy unregistered entirely (Goose's DI container silently
// zero-values an unregistered pointer-to-struct inject:"" field, so that's
// equivalent to rate limiting being off by default; see that type's doc),
// so only NFR-SEC-4's own test needs this variant.
func startAPIWithRateLimit(t *testing.T, svc *directory.Service, policy *envapi.RateLimitPolicy) (base, adminToken string) {
	t.Helper()
	return startAPIWithWebhooks(t, svc, webhook.NewMemoryStore(), func(c types.Container) error {
		return c.Register(func() *envapi.RateLimitPolicy { return policy }, "", true)
	})
}

// startAPIWithQuota is startAPIWithWebhooks plus a registered
// *envapi.QuotaPolicy — every other test in this file leaves QuotaPolicy
// unregistered entirely (the same zero-value-when-unregistered behavior
// RateLimitPolicy's doc explains), so only MessageController's own quota
// test needs this variant.
func startAPIWithQuota(t *testing.T, svc *directory.Service, policy *envapi.QuotaPolicy) (base, adminToken string) {
	t.Helper()
	return startAPIWithWebhooks(t, svc, webhook.NewMemoryStore(), func(c types.Container) error {
		return c.Register(func() *envapi.QuotaPolicy { return policy }, "", true)
	})
}

// startAPIWithRedrive is startAPIWithWebhooks plus a registered
// *envapi.RedrivePolicy wired to dispatcher — every other test in this file
// leaves RedrivePolicy unregistered entirely (the same zero-value-when-
// unregistered behavior RateLimitPolicy's doc explains: Goose's DI
// container silently zero-values an unregistered pointer-to-struct
// inject:"" field), so only the redrive endpoint's own test needs this
// variant. Callers pass the same store the dispatcher itself was built
// against, so ListSubscriptions/ListAttempts (what WebhookController's
// other handlers read) and Redrive (what this wires in) see the same data.
func startAPIWithRedrive(t *testing.T, svc *directory.Service, store webhook.Store, dispatcher *webhook.Dispatcher) (base, adminToken string) {
	t.Helper()
	return startAPIWithWebhooks(t, svc, store, func(c types.Container) error {
		return c.Register(func() *envapi.RedrivePolicy { return &envapi.RedrivePolicy{Dispatcher: dispatcher} }, "", true)
	})
}

// startAPIWithWebhooks boots the real api platform (app.AppModule ->
// internal/api's routes) against svc and store, on a reserved-then-released
// loopback port (the stock Goose api platform has no ephemeral-port/
// listener-discovery hook like our custom platforms do, so a port is
// grabbed and freed just before Boot binds it — the standard trick for
// handing a fixed port to a library that doesn't support port 0
// introspection).
//
// This uses core.NewKernel().Start, not goose.Start: the latter runs
// every instance through a single package-level kernel
// (goose.defaultKernel), so a second test in this package calling
// goose.Start would try to register "vhosts", "/health", etc. a second
// time against routes the first test's kernel already holds and get
// ErrDuplicateRoute. A fresh kernel per test avoids that.
//
// goose.Start (and so core.NewKernel().Start) blocks for the lifetime of
// a single-instance api platform: runSingle calls app.Run synchronously,
// and api.App.Run only returns on an internal error or an OS
// SIGINT/SIGTERM — there's no other shutdown hook available before the
// call returns (its "stop" closure is itself part of that same blocked
// return). So this runs Start in a goroutine and never calls stop: the
// goroutine and its listener leak for the test binary's lifetime, which
// is harmless since each test reserves its own fresh port and the
// process exits at suite end.
func startAPIWithWebhooks(t *testing.T, svc *directory.Service, store webhook.Store, extra ...func(types.Container) error) (base, adminToken string) {
	t.Helper()

	port := reservePort(t)
	admin := "env_test_admin_" + uuid.NewString()
	platform := api.NewPlatform(api.WithName("test-api"), api.WithHost("127.0.0.1"), api.WithPort(port))
	initializers := []func(types.Container) error{
		func(c types.Container) error {
			return c.Register(func() *directory.Service { return svc }, "", true)
		},
		func(c types.Container) error {
			// A fresh maildir backend per API instance under this test's
			// own t.TempDir() — real storage.Store, no Postgres dependency,
			// consistent with how this file already stands other
			// lightweight/in-memory dependencies up per test.
			msgStore := maildir.New(t.TempDir())
			return c.Register(func() storage.Store { return msgStore }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() webhook.Store { return store }, "", true)
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
			// MessageController's inject:"" fields — bare interfaces, so
			// every test booting this module must register them (Goose's DI
			// container hard-errors on an unregistered bare interface field,
			// unlike a pointer-to-struct like QuotaPolicy/RateLimitPolicy/
			// RedrivePolicy, which zero-values safely instead).
			return c.Register(func() queue.Backend { return queue.NewMemoryBackend() }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() webhook.Enqueuer { return webhook.NewDispatcher(store, webhook.NewMemoryEventQueue()) }, "", true)
		},
	}
	initializers = append(initializers, extra...)

	// Errors here (e.g. a bind failure) surface indirectly: waitReady below
	// times out and fails the test. Calling any t.* method from this
	// goroutine would be unsafe — it outlives the test on the (expected)
	// success path, since Start only returns on error or OS signal.
	go func() {
		_, _ = core.NewKernel().Start(goose.API(platform, &app.AppModule{}, initializers))
	}()

	addr := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitReady(t, addr+"/health")
	return addr, admin
}

// startAPIForDataTest is startAPIWithWebhooks plus returning the
// maildir-backed storage.Store the API instance was actually wired to, so
// NFR-COMP-2's export/delete test can write messages into the exact store
// the running instance reads from — every other test in this file doesn't
// need that access, so this duplicates a little of startAPIWithWebhooks's
// body rather than complicating that shared helper's signature for one
// caller.
func startAPIForDataTest(t *testing.T, svc *directory.Service) (base, adminToken string, msgStore storage.Store) {
	t.Helper()

	port := reservePort(t)
	admin := "env_test_admin_" + uuid.NewString()
	store := maildir.New(t.TempDir())
	webhookStore := webhook.NewMemoryStore()
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
			return c.Register(func() queue.Backend { return queue.NewMemoryBackend() }, "", true)
		},
		func(c types.Container) error {
			return c.Register(func() webhook.Enqueuer { return webhook.NewDispatcher(webhookStore, webhook.NewMemoryEventQueue()) }, "", true)
		},
	}

	go func() {
		_, _ = core.NewKernel().Start(goose.API(platform, &app.AppModule{}, initializers))
	}()

	addr := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitReady(t, addr+"/health")
	return addr, admin, store
}

func reservePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reservePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func waitReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", url)
}

// newService intentionally does not truncate vhosts/mailboxes/dkim_keys:
// see internal/directory/service_test.go's newService for why (those
// tables are shared with that package's own tests against the same
// database, and go test runs packages concurrently).
func newService(t *testing.T) *directory.Service {
	t.Helper()
	db := dbtest.DB(t)
	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	enc, err := kms.NewAESGCMEncryptor(bytes.Repeat([]byte("k"), kms.KeySize))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	return directory.New(db, enc)
}

// createAccount creates a fresh account (admin-gated) via POST /accounts
// and returns its ID and auto-issued token — the entry point every
// self-serve vhost-creation test starts from (AccountController.
// CreateAccount mints the account's first token in the same response it
// creates the account in).
func createAccount(t *testing.T, base, admin string) (accountID, token string) {
	t.Helper()
	status, resp := doJSON(t, http.MethodPost, base+"/accounts", admin,
		map[string]any{"name": t.Name() + "-" + uuid.NewString()})
	if status != http.StatusCreated {
		t.Fatalf("create account: status=%d body=%v", status, resp)
	}
	data := resp["data"].(map[string]any)
	account := data["account"].(map[string]any)
	tok := data["token"].(map[string]any)
	accountID, _ = account["id"].(string)
	token, _ = tok["token"].(string)
	if accountID == "" || token == "" {
		t.Fatalf("expected a non-empty account ID and token: %+v", resp)
	}
	return accountID, token
}

// createVhost creates a vhost under accountID (self-serve — token is
// either that account's own token or an admin token) via
// POST /accounts/:accountId/vhosts and returns its ID.
func createVhost(t *testing.T, base, token, accountID, domain string) string {
	t.Helper()
	status, resp := doJSON(t, http.MethodPost, base+"/accounts/"+accountID+"/vhosts", token,
		map[string]any{"domain": domain})
	if status != http.StatusCreated {
		t.Fatalf("create vhost: status=%d body=%v", status, resp)
	}
	id, _ := resp["data"].(map[string]any)["id"].(string)
	if id == "" {
		t.Fatalf("expected a non-empty vhost ID: %+v", resp)
	}
	return id
}

// doJSON issues an authenticated request (FR-5.2: every endpoint requires
// a bearer token) — token is typically the admin token from startAPI, or
// an account-scoped token minted via POST .../tokens.
func doJSON(t *testing.T, method, url, token string, body any) (int, map[string]any) {
	t.Helper()

	var reqBody *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	var parsed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response from %s %s: %v", method, url, err)
	}
	return resp.StatusCode, parsed
}

// doJSONWithClientIP is doJSON plus an X-Forwarded-For header — only
// NFR-SEC-4's rate-limit test needs to control the apparent client IP;
// every other test leaves it unset (see RateLimitPolicy's doc on why that
// makes rate limiting a no-op, independent of whether a policy is even
// registered).
func doJSONWithClientIP(t *testing.T, method, url, token, clientIP string, body any) (int, map[string]any) {
	t.Helper()

	var reqBody *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("X-Forwarded-For", clientIP)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	var parsed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode response from %s %s: %v", method, url, err)
	}
	return resp.StatusCode, parsed
}

// countingLimiter is a deterministic, in-process fake for apiLimiter
// (unexported, so this can't name it directly — it's satisfied
// structurally): the first `allow` calls for a given key succeed, every
// call after that fails, with no real time-based refill. Real refill
// behavior is already covered by internal/ratelimit.PostgresLimiter's own
// tests; this test only needs to prove internal/api wires a limiter's
// verdict into a 429, correctly scoped per key.
type countingLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	allow  int
}

func newCountingLimiter(allow int) *countingLimiter {
	return &countingLimiter{counts: make(map[string]int), allow: allow}
}

func (l *countingLimiter) Allow(_ context.Context, key string, _, _ float64) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[key]++
	return l.counts[key] <= l.allow, nil
}

// TestAPIRateLimitReturns429WhenExceeded covers NFR-SEC-4: a dedicated
// per-client-IP rate limit, distinct from FR-5.2 token auth, keyed off
// X-Forwarded-For.
func TestAPIRateLimitReturns429WhenExceeded(t *testing.T) {
	svc := newService(t)
	limiter := newCountingLimiter(2)
	policy := &envapi.RateLimitPolicy{Limiter: limiter, Capacity: 2, RefillPerSecond: 1}
	base, admin := startAPIWithRateLimit(t, svc, policy)

	const ip = "203.0.113.5"
	for i := 0; i < 2; i++ {
		status, _ := doJSONWithClientIP(t, http.MethodGet, base+"/vhosts", admin, ip, nil)
		if status != http.StatusOK {
			t.Fatalf("request %d from %s: expected 200, got %d", i, ip, status)
		}
	}

	status, _ := doJSONWithClientIP(t, http.MethodGet, base+"/vhosts", admin, ip, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after exceeding the limit, got %d", status)
	}

	// A different client IP has its own bucket.
	status, _ = doJSONWithClientIP(t, http.MethodGet, base+"/vhosts", admin, "203.0.113.9", nil)
	if status != http.StatusOK {
		t.Fatalf("a different client IP should not share %s's exhausted bucket, got %d", ip, status)
	}

	// No X-Forwarded-For at all -> rate limiting no-ops (RateLimitPolicy's
	// doc), so this still succeeds even though ip's bucket is exhausted.
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("a request with no X-Forwarded-For should not be rate limited, got %d", status)
	}
}

// TestUpdateVhostPolicy covers NFR-COMP-1's retention window (and the rest
// of FR-1.2's policy fields) actually being settable through the API, not
// just modeled and stuck at zero.
func TestUpdateVhostPolicy(t *testing.T) {
	svc := newService(t)
	base, admin := startAPI(t, svc)
	accountID, _ := createAccount(t, base, admin)
	vhostID := createVhost(t, base, admin, accountID, t.Name()+"-"+uuid.NewString()+".test")

	status, resp := doJSON(t, http.MethodPatch, base+"/vhosts/"+vhostID+"/policy", admin, map[string]any{
		"maxMessageBytes":         float64(1 << 20),
		"dailyQuota":              500,
		"spamRejectThreshold":     8.5,
		"spamQuarantineThreshold": 5.0,
		"retentionDays":           30,
	})
	if status != http.StatusOK {
		t.Fatalf("update policy: status=%d body=%v", status, resp)
	}
	data := resp["data"].(map[string]any)
	if data["retentionDays"] != float64(30) || data["dailyQuota"] != float64(500) {
		t.Fatalf("unexpected policy in update response: %+v", data)
	}

	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("get vhost: status=%d body=%v", status, resp)
	}
	data = resp["data"].(map[string]any)
	if data["retentionDays"] != float64(30) {
		t.Fatalf("policy not persisted: %+v", data)
	}
}

// TestVhostDataExportAndDelete covers NFR-COMP-2: a tenant's actual
// message data must be reachable for export and erasable on request via
// the API, not solely via direct DB access.
func TestVhostDataExportAndDelete(t *testing.T) {
	svc := newService(t)
	base, admin, msgStore := startAPIForDataTest(t, svc)
	accountID, _ := createAccount(t, base, admin)

	domain := t.Name() + "-" + uuid.NewString() + ".test"
	vhostID := createVhost(t, base, admin, accountID, domain)

	status, resp := doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/mailboxes", admin,
		map[string]any{"localPart": "alice", "password": "s3cret"})
	if status != http.StatusCreated {
		t.Fatalf("create mailbox: status=%d body=%v", status, resp)
	}

	// Write directly into the same store the running instance reads from
	// (there's no SMTP path in this test — mail delivery is exercised
	// elsewhere; this test is specifically about the export/delete API
	// surface over whatever's already stored).
	ctx := context.Background()
	if _, err := msgStore.Write(ctx, domain, "alice/INBOX", strings.NewReader("hello from alice's inbox")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/export", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("export: status=%d body=%v", status, resp)
	}
	data := resp["data"].(map[string]any)
	if data["vhost"].(map[string]any)["id"] != vhostID {
		t.Fatalf("export vhost mismatch: %+v", data["vhost"])
	}
	mailboxes, _ := data["mailboxes"].([]any)
	if len(mailboxes) != 1 || mailboxes[0].(map[string]any)["localPart"] != "alice" {
		t.Fatalf("expected 1 exported mailbox for alice, got %+v", mailboxes)
	}
	messages, _ := data["messages"].([]any)
	if len(messages) != 1 {
		t.Fatalf("expected 1 exported message, got %+v", messages)
	}
	msg := messages[0].(map[string]any)
	if msg["mailbox"] != "alice/INBOX" {
		t.Fatalf("unexpected exported message mailbox: %+v", msg)
	}
	decoded, err := base64.StdEncoding.DecodeString(msg["body"].(string))
	if err != nil || string(decoded) != "hello from alice's inbox" {
		t.Fatalf("exported body mismatch: decoded=%q err=%v", decoded, err)
	}

	// Erase.
	status, resp = doJSON(t, http.MethodDelete, base+"/vhosts/"+vhostID+"/data", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("delete data: status=%d body=%v", status, resp)
	}
	if resp["data"].(map[string]any)["messagesDeleted"] != float64(1) {
		t.Fatalf("expected messagesDeleted=1, got %+v", resp["data"])
	}

	// A second export now shows no messages.
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/export", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("export after delete: status=%d body=%v", status, resp)
	}
	messages, _ = resp["data"].(map[string]any)["messages"].([]any)
	if len(messages) != 0 {
		t.Fatalf("expected no messages after delete, got %+v", messages)
	}

	// Mailbox credentials are untouched by data deletion (FR-3.1/7.2 auth
	// still needs to work) — only message content is erased.
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/mailboxes", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list mailboxes after delete: status=%d body=%v", status, resp)
	}
	mailboxes, _ = resp["data"].([]any)
	if len(mailboxes) != 1 {
		t.Fatalf("expected the mailbox to survive data deletion, got %+v", mailboxes)
	}
}

func TestVhostAndMailboxCRUD(t *testing.T) {
	svc := newService(t)
	base, admin := startAPI(t, svc)
	accountID, _ := createAccount(t, base, admin)

	// Create vhost.
	status, resp := doJSON(t, http.MethodPost, base+"/accounts/"+accountID+"/vhosts", admin, map[string]any{"domain": t.Name() + "-" + uuid.NewString() + ".test"})
	if status != http.StatusCreated {
		t.Fatalf("create vhost: status=%d body=%v", status, resp)
	}
	vhost := resp["data"].(map[string]any)
	vhostID, _ := vhost["id"].(string)
	if vhostID == "" || vhost["dkimDnsRecord"] == "" || vhost["dkimDnsRecord"] == nil {
		t.Fatalf("unexpected created vhost: %+v", vhost)
	}
	if _, leaked := vhost["dkimKey"]; leaked {
		t.Fatalf("response leaked a dkimKey field: %+v", vhost)
	}

	// List vhosts — paginate through every page rather than trusting the
	// first one contains this test's vhost: vhosts is a shared,
	// un-truncated table across every test package/run (see
	// internal/directory/service_test.go's TestServiceListVhosts, fixed
	// the same way for the same reason), and "id ASC" ordering over UUIDs
	// gives this test's newly created row no guaranteed position in a
	// corpus that's grown well past one 100-row page.
	found := false
	cursor := ""
	for {
		url := base + "/vhosts"
		if cursor != "" {
			url += "?cursor=" + cursor
		}
		status, resp = doJSON(t, http.MethodGet, url, admin, nil)
		if status != http.StatusOK {
			t.Fatalf("list vhosts: status=%d body=%v", status, resp)
		}
		list, _ := resp["data"].([]any)
		for _, v := range list {
			if v.(map[string]any)["id"] == vhostID {
				found = true
			}
		}
		if found {
			break
		}
		next, _ := resp["meta"].(map[string]any)["nextCursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if !found {
		t.Fatalf("created vhost %q not found across any page of /vhosts", vhostID)
	}

	// Get vhost.
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID, admin, nil)
	if status != http.StatusOK || resp["data"].(map[string]any)["id"] != vhostID {
		t.Fatalf("get vhost: status=%d body=%v", status, resp)
	}

	// Create mailbox.
	status, resp = doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/mailboxes", admin,
		map[string]any{"localPart": "alice", "password": "s3cret"})
	if status != http.StatusCreated {
		t.Fatalf("create mailbox: status=%d body=%v", status, resp)
	}
	mailbox := resp["data"].(map[string]any)
	mailboxID, _ := mailbox["id"].(string)
	if mailboxID == "" || mailbox["localPart"] != "alice" {
		t.Fatalf("unexpected created mailbox: %+v", mailbox)
	}
	for _, leakedField := range []string{"passwordHash", "password"} {
		if _, leaked := mailbox[leakedField]; leaked {
			t.Fatalf("response leaked field %q: %+v", leakedField, mailbox)
		}
	}

	// Create mailbox under an unknown vhost -> 404 (still admin-authorized,
	// just no such vhost).
	status, _ = doJSON(t, http.MethodPost, base+"/vhosts/does-not-exist/mailboxes", admin,
		map[string]any{"localPart": "bob", "password": "x"})
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 creating mailbox under unknown vhost, got %d", status)
	}

	// List mailboxes.
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/mailboxes", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list mailboxes: status=%d body=%v", status, resp)
	}
	mailboxList, _ := resp["data"].([]any)
	if len(mailboxList) != 1 {
		t.Fatalf("expected 1 mailbox, got %+v", mailboxList)
	}

	// Get mailbox.
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/mailboxes/"+mailboxID, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("get mailbox: status=%d", status)
	}

	// Deactivate vhost (FR-1.4).
	status, _ = doJSON(t, http.MethodPatch, base+"/vhosts/"+vhostID+"/deactivate", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("deactivate vhost: status=%d", status)
	}
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID, admin, nil)
	if status != http.StatusOK || resp["data"].(map[string]any)["active"] != false {
		t.Fatalf("expected vhost inactive after deactivate: status=%d body=%v", status, resp)
	}

	// Delete mailbox.
	status, _ = doJSON(t, http.MethodDelete, base+"/vhosts/"+vhostID+"/mailboxes/"+mailboxID, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("delete mailbox: status=%d", status)
	}
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/mailboxes/"+mailboxID, admin, nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 fetching deleted mailbox, got %d", status)
	}
}

// TestListMailboxesPagination exercises FR-5.4's cursor pagination over
// real HTTP — the API-layer half of the other 5 list endpoints' pagination
// gap (internal/directory's TestListMailboxesPage already covers the
// storage layer directly). Unlike /vhosts, a freshly created vhost's own
// mailboxes aren't shared with any other test, so this can assert an exact
// page-by-page sweep rather than just "found somewhere."
func TestListMailboxesPagination(t *testing.T) {
	svc := newService(t)
	base, admin := startAPI(t, svc)
	accountID, _ := createAccount(t, base, admin)
	vhostID := createVhost(t, base, admin, accountID, t.Name()+"-"+uuid.NewString()+".test")

	const total = 5
	for i := 0; i < total; i++ {
		status, resp := doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/mailboxes", admin,
			map[string]any{"localPart": fmt.Sprintf("user%d", i), "password": "s3cret"})
		if status != http.StatusCreated {
			t.Fatalf("create mailbox %d: status=%d body=%v", i, status, resp)
		}
	}

	seen := make(map[string]bool)
	cursor := ""
	for {
		url := base + "/vhosts/" + vhostID + "/mailboxes?limit=2"
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		status, resp := doJSON(t, http.MethodGet, url, admin, nil)
		if status != http.StatusOK {
			t.Fatalf("list mailboxes: status=%d body=%v", status, resp)
		}
		list, _ := resp["data"].([]any)
		if len(list) == 0 {
			break
		}
		if len(list) > 2 {
			t.Fatalf("requested limit=2 but got %d rows: %+v", len(list), list)
		}
		var lastID string
		for _, m := range list {
			id := m.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("mailbox %q returned on more than one page", id)
			}
			seen[id] = true
			lastID = id
		}
		next, _ := resp["meta"].(map[string]any)["nextCursor"].(string)
		if len(list) < 2 {
			if next != "" {
				t.Fatalf("expected no nextCursor on a short final page, got %q", next)
			}
			break
		}
		if next != lastID {
			t.Fatalf("expected nextCursor %q to be the last row's ID %q", next, lastID)
		}
		cursor = next
	}

	if len(seen) != total {
		t.Fatalf("expected %d distinct mailboxes across all pages, got %d", total, len(seen))
	}
}

func TestCreateVhostRejectsEmptyDomain(t *testing.T) {
	svc := newService(t)
	base, admin := startAPI(t, svc)
	accountID, _ := createAccount(t, base, admin)

	status, _ := doJSON(t, http.MethodPost, base+"/accounts/"+accountID+"/vhosts", admin, map[string]any{"domain": ""})
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty domain, got %d", status)
	}
}

func TestGetVhostUnknownReturns404(t *testing.T) {
	svc := newService(t)
	base, admin := startAPI(t, svc)

	status, _ := doJSON(t, http.MethodGet, base+"/vhosts/does-not-exist", admin, nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", status)
	}
}

// TestAPIRequiresAuthentication covers FR-5.2: every endpoint rejects a
// request with no (or a garbage) bearer token; an account owns one or more
// vhosts under one token (no 1:1 account:vhost mapping); an account's own
// token can self-serve create vhosts and mint/revoke further tokens for
// itself with no further admin involvement past the account's own
// creation; and none of that reaches another account's resources or
// platform-level endpoints.
func TestAPIRequiresAuthentication(t *testing.T) {
	svc := newService(t)
	base, admin := startAPI(t, svc)

	// No Authorization header at all.
	status, _ := doJSON(t, http.MethodGet, base+"/vhosts", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no token, got %d", status)
	}

	// Garbage token.
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts", "not-a-real-token", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 with an invalid token, got %d", status)
	}

	// Admin creates two accounts, each auto-issued its own token; each
	// account then self-serves its own vhost(s) with no further admin
	// involvement. accountA owns two vhosts through the same token,
	// proving the 1-account-many-vhosts model actually works end to end.
	accountA, tokenA := createAccount(t, base, admin)
	accountB, tokenB := createAccount(t, base, admin)
	vhostA1 := createVhost(t, base, tokenA, accountA, t.Name()+"-a1-"+uuid.NewString()+".test")
	vhostA2 := createVhost(t, base, tokenA, accountA, t.Name()+"-a2-"+uuid.NewString()+".test")
	vhostB := createVhost(t, base, tokenB, accountB, t.Name()+"-b-"+uuid.NewString()+".test")

	// An account-scoped token cannot self-serve a vhost under a different
	// account.
	status, _ = doJSON(t, http.MethodPost, base+"/accounts/"+accountB+"/vhosts", tokenA, map[string]any{"domain": "should-fail.test"})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for accountA's token creating a vhost under accountB, got %d", status)
	}

	// An account-scoped token cannot reach platform-level endpoints.
	status, _ = doJSON(t, http.MethodGet, base+"/accounts", tokenA, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin token listing every account, got %d", status)
	}
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts", tokenA, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for a non-admin token listing every vhost, got %d", status)
	}

	// accountA's token can access both of its own vhosts...
	for _, id := range []string{vhostA1, vhostA2} {
		status, _ = doJSON(t, http.MethodGet, base+"/vhosts/"+id, tokenA, nil)
		if status != http.StatusOK {
			t.Fatalf("expected accountA's token to read its own vhost %s, got %d", id, status)
		}
	}
	// ...but not vhostB, a real vhost belonging to a different account...
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostB, tokenA, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for accountA's token reading vhostB, got %d", status)
	}
	// ...and a vhost ID that doesn't exist at all gets the identical 403,
	// not a distinguishable 404 — collapsing both cases avoids a
	// cross-tenant vhost-ID existence oracle a naive 404-vs-403 split would
	// introduce (see requireVhostAccountAccess's doc).
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts/does-not-exist", tokenA, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 (not 404) for a non-admin token reading a nonexistent vhost, got %d", status)
	}

	// accountA's own token can mint a further token for itself (self-service
	// rotation)...
	status, resp := doJSON(t, http.MethodPost, base+"/accounts/"+accountA+"/tokens", tokenA, map[string]any{"label": "ci"})
	if status != http.StatusCreated {
		t.Fatalf("create token: status=%d body=%v", status, resp)
	}
	tokenA2 := resp["data"].(map[string]any)["token"].(string)
	if tokenA2 == "" {
		t.Fatalf("expected a non-empty raw token in the create-token response: %+v", resp)
	}
	// ...but not for a different account.
	status, _ = doJSON(t, http.MethodPost, base+"/accounts/"+accountB+"/tokens", tokenA, map[string]any{"label": "ci"})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for accountA's token minting a token under accountB, got %d", status)
	}

	// Listing accountA's tokens shows both the auto-issued "default" one
	// and the freshly minted "ci" one, with no raw value leaked.
	status, resp = doJSON(t, http.MethodGet, base+"/accounts/"+accountA+"/tokens", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list tokens: status=%d body=%v", status, resp)
	}
	tokens, _ := resp["data"].([]any)
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens (default + ci), got %+v", tokens)
	}
	var tokenA2ID string
	for _, tk := range tokens {
		entry := tk.(map[string]any)
		if entry["label"] == "ci" {
			tokenA2ID = entry["id"].(string)
		}
		if _, leaked := entry["token"]; leaked {
			t.Fatalf("ListTokens leaked the raw token: %+v", entry)
		}
	}
	if tokenA2ID == "" {
		t.Fatalf("expected to find the ci-labeled token: %+v", tokens)
	}

	// A revoked token stops working, but the account's other (original)
	// token is unaffected.
	status, _ = doJSON(t, http.MethodDelete, base+"/accounts/"+accountA+"/tokens/"+tokenA2ID, tokenA, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke token: status=%d", status)
	}
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostA1, tokenA2, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a revoked token, got %d", status)
	}
	status, _ = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostA1, tokenA, nil)
	if status != http.StatusOK {
		t.Fatalf("expected accountA's original token to still work after revoking a different one, got %d", status)
	}
}

// TestAuditLogRecordsAdminActions covers NFR-COMP-4: mutating admin
// actions produce a queryable audit trail (who did what, when).
func TestAuditLogRecordsAdminActions(t *testing.T) {
	svc := newService(t)
	base, admin := startAPI(t, svc)
	accountID, _ := createAccount(t, base, admin)
	vhostID := createVhost(t, base, admin, accountID, t.Name()+"-"+uuid.NewString()+".test")

	status, resp := doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/mailboxes", admin,
		map[string]any{"localPart": "alice", "password": "s3cret"})
	if status != http.StatusCreated {
		t.Fatalf("create mailbox: status=%d body=%v", status, resp)
	}

	status, _ = doJSON(t, http.MethodPatch, base+"/vhosts/"+vhostID+"/deactivate", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("deactivate vhost: status=%d", status)
	}

	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/audit-log", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list audit log: status=%d body=%v", status, resp)
	}
	entries, _ := resp["data"].([]any)
	if len(entries) != 3 {
		t.Fatalf("expected 3 audit entries (vhost.create, mailbox.create, vhost.deactivate), got %+v", entries)
	}
	// Newest first.
	if entries[0].(map[string]any)["action"] != "vhost.deactivate" || entries[0].(map[string]any)["actor"] != "admin" {
		t.Fatalf("unexpected newest entry: %+v", entries[0])
	}
	if entries[1].(map[string]any)["action"] != "mailbox.create" {
		t.Fatalf("unexpected middle entry: %+v", entries[1])
	}
	if entries[2].(map[string]any)["action"] != "vhost.create" {
		t.Fatalf("unexpected oldest entry: %+v", entries[2])
	}
}
