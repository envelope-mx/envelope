// Package smtp is a custom Goose platform (TRD §2.1) wrapping go-smtp for
// the inbound (FR-2.x) and submission (FR-3.x) roles.
package smtp

import (
	"context"
	"crypto/tls"

	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/filter"
	"github.com/isaiahiroko/envelope/internal/queue"
	"github.com/isaiahiroko/envelope/internal/storage"
	"github.com/isaiahiroko/envelope/internal/webhook"
)

// RateLimiter is the shared, cross-replica rate-limit contract FR-2.3
// needs — satisfied by *ratelimit.PostgresLimiter in production. An
// interface here (rather than importing internal/ratelimit's concrete
// type) so tests can inject a fake without a database.
type RateLimiter interface {
	Allow(ctx context.Context, key string, capacity, refillPerSecond float64) (bool, error)
}

// Mode selects which role this Platform instance boots: Inbound (port 25,
// FR-2.x) or Submission (port 587, FR-3.x). Both share one Goose platform
// package because they're both go-smtp servers differing only in Session
// behavior, per TRD §2.1 ("internal/platform/smtp for inbound +
// submission").
type Mode int

const (
	ModeInbound Mode = iota
	ModeSubmission
)

func (m Mode) String() string {
	if m == ModeSubmission {
		return "smtp-submission"
	}
	return "smtp-inbound"
}

// OutboxMailbox re-exports storage.OutboxMailbox for callers already
// importing this package (submission.go itself, and every test that
// verifies a staged body) — see that constant's doc for why it lives in
// internal/storage instead.
const OutboxMailbox = storage.OutboxMailbox

// Config configures a smtp Platform instance.
type Config struct {
	Mode Mode
	Name string
	Addr string // e.g. "127.0.0.1:25" or ":587"

	// Domain is the HELO/EHLO domain advertised to peers.
	Domain string

	// TLSConfig enables STARTTLS when set (FR-2.1: offered, not
	// required). nil disables STARTTLS entirely.
	TLSConfig *tls.Config

	// AllowInsecureAuth permits AUTH without a prior STARTTLS. Dev/test
	// only — FR-3.1 requires submission auth happen over TLS.
	AllowInsecureAuth bool

	// MaxMessageBytes overrides go-smtp's default max message size when
	// non-zero. This is the hard, server-wide ceiling FR-2.7's mid-transfer
	// rejection relies on (go-smtp's own DATA reader enforces it while
	// reading, not after); a recipient vhost's smaller FR-1.2
	// MaxMessageBytes is additionally enforced in inboundSession.Data,
	// best-effort, after the (already server-wide-bounded) body is read —
	// see that method's doc for why a true per-connection dynamic mid-
	// stream limit isn't possible with go-smtp's API.
	MaxMessageBytes int64

	Directory directory.Directory
	Store     storage.Store
	Queue     queue.Backend // only used in ModeSubmission

	// Filter runs the FR-2.4/2.5 accept/quarantine/reject pipeline.
	// Required for ModeInbound; unused in ModeSubmission (filtering only
	// concerns inbound acceptance, docs/ENVELOPE.md Phase 4 scope).
	Filter *filter.Pipeline

	// RateLimiter is nil-able: nil disables FR-2.3 rate limiting entirely
	// (e.g. in tests that don't care about it). Capacity/refill values of
	// zero disable that specific dimension (IP or sender) while leaving
	// the other active. Used only in ModeInbound.
	RateLimiter                                             RateLimiter
	RateLimitIPCapacity, RateLimitIPRefillPerSecond         float64
	RateLimitSenderCapacity, RateLimitSenderRefillPerSecond float64

	// Quota enforces FR-3.7's per-vhost daily sending quota, checked once
	// per accepted submission. Reuses the RateLimiter shape rather than a
	// bespoke calendar-day counter: a token bucket with capacity
	// Vhost.DailyQuota and a refill rate spread evenly across 24h
	// approximates "N messages/day" as a rolling window, which is at least
	// as correct as a hard calendar-day reset (no midnight burst) and
	// reuses internal/ratelimit.PostgresLimiter's already-tested Postgres
	// row-locking instead of building a second quota-tracking mechanism.
	// nil disables quota enforcement entirely; a given vhost's
	// DailyQuota <= 0 disables it for that vhost specifically (the same
	// "0 means unconfigured" convention FR-1.2's other thresholds use).
	// Used only in ModeSubmission.
	Quota RateLimiter

	// Webhooks fires FR-2.5's message.received event on inbound accept/
	// quarantine (Phase 4 built the verdict and storage routing but left
	// this call site unwired — see docs/ENVELOPE.md Phase 4/5), and
	// message.queued once per accepted submission (see
	// submissionSession.fireQueued). nil disables firing entirely.
	// Enqueue only durably persists a delivery row (a fast local DB
	// insert, the same kind of call s.cfg.Store.Write and
	// s.cfg.RateLimiter.Allow already make inline in this same handler) —
	// the actual outbound HTTP POST to a tenant endpoint happens later,
	// from webhook.Dispatcher.Run's background loop, so a slow tenant
	// endpoint still can't block mail acceptance (FR-6.3). Used in both
	// ModeInbound and ModeSubmission.
	Webhooks webhook.Enqueuer
}
