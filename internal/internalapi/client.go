package internalapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/queue"
	"github.com/isaiahiroko/envelope/internal/storage"
	"github.com/isaiahiroko/envelope/internal/webhook"
)

// httpClient is the shared request plumbing every typed client below
// wraps — one token, one base URL, one http.Client with a real timeout
// (an unreachable internal API must fail a mail transaction within a
// bounded time, not hang the SMTP session indefinitely).
type httpClient struct {
	baseURL string
	token   string
	hc      *http.Client
}

func newHTTPClient(baseURL, token string) *httpClient {
	return &httpClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		hc:      &http.Client{Timeout: 10 * time.Second},
	}
}

// doJSON marshals reqBody (nil for none), sends it, and unmarshals the
// response into respBody (nil to discard). A non-2xx response is always
// an error, built from the server's errorResponse body when present.
func (c *httpClient) doJSON(ctx context.Context, method, path string, reqBody, respBody any) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("internalapi: encode request: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("internalapi: build request: %w", err)
	}
	req.Header.Set(HeaderToken, c.token)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("internalapi: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return responseError(method, path, resp)
	}
	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("internalapi: decode response: %w", err)
		}
	}
	return nil
}

func responseError(method, path string, resp *http.Response) error {
	var errResp errorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	if errResp.Error == "" {
		errResp.Error = resp.Status
	}
	return fmt.Errorf("internalapi: %s %s: %d %s", method, path, resp.StatusCode, errResp.Error)
}

// unsupported is what every Client method outside wire.go's eight
// operations returns — see wire.go's package doc for why these exist at
// all (Go interface satisfaction) but are never meant to succeed (no
// role's token is ever granted the scope that would make a server round
// trip meaningful).
func unsupported(method string) error {
	return fmt.Errorf(
		"internalapi: %s is not exposed to SMTP-facing roles over the internal API (least-privilege by design, mirroring deploy/postgres/roles.sql's SQL-level grants)",
		method)
}

// DirectoryClient implements directory.Directory over the internal API.
type DirectoryClient struct{ c *httpClient }

// NewDirectoryClient returns a DirectoryClient calling baseURL
// (cmd/envelope/main.go's ENVELOPE_INTERNAL_API_URL) with token (that
// role's ENVELOPE_INTERNAL_TOKEN_<ROLE>).
func NewDirectoryClient(baseURL, token string) *DirectoryClient {
	return &DirectoryClient{c: newHTTPClient(baseURL, token)}
}

var _ directory.Directory = (*DirectoryClient)(nil)

func (d *DirectoryClient) Vhost(ctx context.Context, domain string) (directory.Vhost, bool) {
	var resp vhostResponse
	if err := d.c.doJSON(ctx, http.MethodPost, "/internal/v1/directory/vhost", vhostRequest{Domain: domain}, &resp); err != nil {
		// directory.Directory.Vhost has no error return (every existing
		// implementation already fails closed this way — see
		// directory.Service.Vhost's own gorm.ErrRecordNotFound handling),
		// so an unreachable internal API surfaces identically to "domain
		// not registered": inbound rejects the recipient, submission
		// refuses to sign. A real, new availability dependency this
		// architecture introduces (the api role's process must be up for
		// SMTP-facing roles to work at all) — stated here plainly, not
		// hidden behind this fail-closed return.
		return directory.Vhost{}, false
	}
	if !resp.Found || resp.Vhost == nil {
		return directory.Vhost{}, false
	}

	v := directory.Vhost{
		ID: resp.Vhost.ID, Domain: resp.Vhost.Domain, Active: resp.Vhost.Active, DKIMSelector: resp.Vhost.DKIMSelector,
		MaxMessageBytes: resp.Vhost.MaxMessageBytes, DailyQuota: resp.Vhost.DailyQuota,
		SpamRejectThreshold: resp.Vhost.SpamRejectThreshold, SpamQuarantineThreshold: resp.Vhost.SpamQuarantineThreshold,
		RetentionDays: resp.Vhost.RetentionDays,
	}
	if resp.Vhost.DKIMKeyPEM != "" {
		key, err := pemToRSAKey(resp.Vhost.DKIMKeyPEM)
		if err == nil {
			v.DKIMKey = key
		}
	}
	return v, true
}

// VhostActive is derived from Vhost rather than its own RPC — no server
// endpoint exists for it (see wire.go's package doc: this method is never
// actually called by any of the three migrated roles' real code paths,
// only required by directory.Directory's method set), and deriving it
// this way means it still behaves correctly if that ever changes, for
// free.
func (d *DirectoryClient) VhostActive(ctx context.Context, domain string) bool {
	v, ok := d.Vhost(ctx, domain)
	return ok && v.Active
}

func (d *DirectoryClient) Authenticate(ctx context.Context, vhost, localPart, password string) bool {
	var resp authenticateResponse
	err := d.c.doJSON(ctx, http.MethodPost, "/internal/v1/directory/authenticate",
		authenticateRequest{Vhost: vhost, LocalPart: localPart, Password: password}, &resp)
	if err != nil {
		return false // fail closed, matching every other Directory implementation's own error handling
	}
	return resp.OK
}

// StoreClient implements storage.Store over the internal API.
type StoreClient struct{ c *httpClient }

func NewStoreClient(baseURL, token string) *StoreClient {
	return &StoreClient{c: newHTTPClient(baseURL, token)}
}

var _ storage.Store = (*StoreClient)(nil)

func (s *StoreClient) Write(ctx context.Context, vhost, mailbox string, body io.Reader) (storage.MessageRef, error) {
	u := "/internal/v1/store/write?vhost=" + url.QueryEscape(vhost) + "&mailbox=" + url.QueryEscape(mailbox)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.c.baseURL+u, body)
	if err != nil {
		return storage.MessageRef{}, fmt.Errorf("internalapi: build write request: %w", err)
	}
	req.Header.Set(HeaderToken, s.c.token)

	resp, err := s.c.hc.Do(req)
	if err != nil {
		return storage.MessageRef{}, fmt.Errorf("internalapi: store write: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return storage.MessageRef{}, responseError(http.MethodPost, u, resp)
	}

	var wr writeResponse
	if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
		return storage.MessageRef{}, fmt.Errorf("internalapi: decode write response: %w", err)
	}
	return storage.MessageRef{Vhost: wr.Vhost, Mailbox: wr.Mailbox, Key: wr.Key}, nil
}

// Read streams the response body directly rather than buffering it into
// JSON/base64 first — a message body can be large (up to
// Config.MaxMessageBytes), and this is exactly the "read once, write once"
// shape storage.Store.Read already promises callers everywhere else.
func (s *StoreClient) Read(ctx context.Context, ref storage.MessageRef) (io.ReadCloser, error) {
	u := "/internal/v1/store/read?vhost=" + url.QueryEscape(ref.Vhost) +
		"&mailbox=" + url.QueryEscape(ref.Mailbox) + "&key=" + url.QueryEscape(ref.Key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.c.baseURL+u, nil)
	if err != nil {
		return nil, fmt.Errorf("internalapi: build read request: %w", err)
	}
	req.Header.Set(HeaderToken, s.c.token)

	resp, err := s.c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("internalapi: store read: %w", err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, responseError(http.MethodGet, u, resp)
	}
	return resp.Body, nil // caller Closes, per storage.Store.Read's contract
}

func (s *StoreClient) List(ctx context.Context, vhost, mailbox string) ([]storage.MessageMeta, error) {
	var resp listResponse
	err := s.c.doJSON(ctx, http.MethodPost, "/internal/v1/store/list", listRequest{Vhost: vhost, Mailbox: mailbox}, &resp)
	if err != nil {
		return nil, err
	}
	out := make([]storage.MessageMeta, len(resp.Metas))
	for i, m := range resp.Metas {
		out[i] = storage.MessageMeta{
			Ref:  storage.MessageRef{Vhost: m.Vhost, Mailbox: m.Mailbox, Key: m.Key},
			Size: m.Size, Flags: m.Flags, CreatedAt: m.CreatedAt,
		}
	}
	return out, nil
}

func (s *StoreClient) UpdateFlags(ctx context.Context, ref storage.MessageRef, flags []string) error {
	req := updateFlagsRequest{Vhost: ref.Vhost, Mailbox: ref.Mailbox, Key: ref.Key, Flags: flags}
	return s.c.doJSON(ctx, http.MethodPost, "/internal/v1/store/updateflags", req, nil)
}

// ListVhost/Delete: no SMTP-facing role calls either (retention purge and
// GDPR export, the only current callers, run inside the api role's
// process against the real storage.Store directly — see wire.go's
// package doc).
func (s *StoreClient) ListVhost(ctx context.Context, vhost string) ([]storage.MessageMeta, error) {
	return nil, unsupported("Store.ListVhost")
}

func (s *StoreClient) Delete(ctx context.Context, ref storage.MessageRef) error {
	return unsupported("Store.Delete")
}

// QueueClient implements queue.Backend over the internal API.
type QueueClient struct{ c *httpClient }

func NewQueueClient(baseURL, token string) *QueueClient {
	return &QueueClient{c: newHTTPClient(baseURL, token)}
}

var _ queue.Backend = (*QueueClient)(nil)

func (q *QueueClient) Enqueue(ctx context.Context, job queue.Job) error {
	req := enqueueJobRequest{
		ID: job.ID, Vhost: job.Vhost, From: job.From, To: job.To, BodyRef: job.BodyRef,
		NextAttemptAt: job.NextAttemptAt, CorrelationID: job.CorrelationID,
	}
	return q.c.doJSON(ctx, http.MethodPost, "/internal/v1/queue/enqueue", req, nil)
}

// Dequeue/Complete/Fail/Count: only internal/deliverer calls these, and it
// isn't part of this migration (it initiates outbound connections rather
// than accepting untrusted inbound ones, a different NFR-SEC-5 threat
// profile — see docs/ENVELOPE.md) — it keeps its direct queue.Backend.
func (q *QueueClient) Dequeue(ctx context.Context) (queue.Job, bool, error) {
	return queue.Job{}, false, unsupported("Queue.Dequeue")
}

func (q *QueueClient) Complete(ctx context.Context, id string) error {
	return unsupported("Queue.Complete")
}

func (q *QueueClient) Fail(ctx context.Context, id string, cause error, nextAttemptAt time.Time) error {
	return unsupported("Queue.Fail")
}

func (q *QueueClient) Count(ctx context.Context) (int, error) {
	return 0, unsupported("Queue.Count")
}

// RateLimiterClient implements the single-method RateLimiter shape
// internal/platform/smtp.RateLimiter and internal/ratelimit.PostgresLimiter
// already share, over the internal API. Used for smtp-inbound's IP/sender
// limits and smtp-submission's quota check — the same wire operation
// serves all three, distinguished only by the "key" prefix
// (internal/platform/smtp already does this against the direct
// PostgresLimiter today; nothing here changes that convention).
type RateLimiterClient struct{ c *httpClient }

func NewRateLimiterClient(baseURL, token string) *RateLimiterClient {
	return &RateLimiterClient{c: newHTTPClient(baseURL, token)}
}

func (r *RateLimiterClient) Allow(ctx context.Context, key string, capacity, refillPerSecond float64) (bool, error) {
	var resp rateLimitAllowResponse
	req := rateLimitAllowRequest{Key: key, Capacity: capacity, RefillPerSecond: refillPerSecond}
	if err := r.c.doJSON(ctx, http.MethodPost, "/internal/v1/ratelimit/allow", req, &resp); err != nil {
		return false, err
	}
	return resp.Allowed, nil
}

// WebhookClient implements webhook.Enqueuer over the internal API.
type WebhookClient struct{ c *httpClient }

func NewWebhookClient(baseURL, token string) *WebhookClient {
	return &WebhookClient{c: newHTTPClient(baseURL, token)}
}

var _ webhook.Enqueuer = (*WebhookClient)(nil)

func (w *WebhookClient) Enqueue(ctx context.Context, vhost, eventType string, payload []byte) error {
	req := webhookEnqueueRequest{Vhost: vhost, EventType: eventType, Payload: payload}
	return w.c.doJSON(ctx, http.MethodPost, "/internal/v1/webhook/enqueue", req, nil)
}
