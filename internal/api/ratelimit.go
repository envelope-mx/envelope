package api

import (
	"context"
	"strings"
)

// apiLimiter is the FR-2.3-shaped contract NFR-SEC-4's dedicated per-IP API
// rate limit needs — satisfied by *ratelimit.PostgresLimiter in production,
// the same Allow(ctx, key, capacity, refillPerSecond) shape
// internal/platform/smtp.RateLimiter already defines for its own FR-2.3
// use. Duplicated here rather than imported: this package depending on
// internal/platform/smtp for an interface this small would be backwards
// (smtp already depends on nothing here).
type apiLimiter interface {
	Allow(ctx context.Context, key string, capacity, refillPerSecond float64) (bool, error)
}

// DefaultAPIRateLimitCapacity/RefillPerSecond are generous starting points
// (same framing as internal/platform/smtp's FR-2.3 defaults — not tuned
// production values), used whenever RateLimitPolicy's own fields are unset.
const (
	DefaultAPIRateLimitCapacity        = 60
	DefaultAPIRateLimitRefillPerSecond = 1
)

// RateLimitPolicy is NFR-SEC-4's dedicated per-client-IP API rate limit —
// distinct from FR-5.2 token auth, which only tells a valid credential from
// an invalid one and does nothing to slow an attacker hammering the API
// with credential guesses from one address.
//
// A pointer-to-struct, not a bare bound interface — see AdminToken's doc
// for why Goose's DI container needs that shape to populate an inject:""
// field at all. Unlike AdminToken, this collaborator is meant to be
// optional: nil (or a nil Limiter) disables rate limiting entirely, the
// same "nil disables this dimension" convention
// internal/platform/smtp.Config.RateLimiter already uses. That matters
// here specifically because an unregistered pointer-to-struct inject:""
// field is silently zero-valued by the container rather than erroring the
// way an unregistered *interface* field would (core/container.go's
// create) — so every existing test/deployment that doesn't wire one up
// keeps booting with this feature simply off, instead of failing to start.
//
// The client IP itself comes from an X-Forwarded-For header
// (clientIPFromHeader), not the connection's RemoteAddr: Goose's
// types.Request interface exposes headers but has no RemoteAddr accessor
// at all, so there is no way to reach the raw *http.Request from a
// controller. This depends on an operator-provided reverse proxy setting
// that header — the same reverse-proxy assumption NFR-SEC-1's TLS
// termination decision already documents (Goose's stock api platform has
// no in-process TLS support). Without such a proxy in front of this
// process, this dimension silently no-ops rather than keying every caller
// off one shared, useless bucket; FR-5.2's token auth still protects every
// endpoint regardless of whether this is wired up.
type RateLimitPolicy struct {
	Limiter         apiLimiter
	Capacity        float64
	RefillPerSecond float64
}

// QuotaPolicy wraps the FR-3.7-style per-vhost daily sending quota
// MessageController checks before accepting a send — the same nilable-
// pointer-to-struct shape RateLimitPolicy already uses (see that type's
// doc) so an unregistered QuotaPolicy silently disables quota enforcement
// rather than the container hard-erroring, matching
// internal/platform/smtp/submission.go's Quota == nil no-op posture
// exactly. No Capacity/RefillPerSecond fields here (unlike
// RateLimitPolicy): capacity/refill are always derived per-vhost from
// directory.Vhost.DailyQuota, never a fixed platform default.
type QuotaPolicy struct {
	Limiter apiLimiter
}

// clientIPFromHeader extracts the originating client address from an
// X-Forwarded-For header value — the first entry is the original client;
// any further entries are intermediate proxies. Returns "" for an empty
// header (either unset, or the request reached this process directly with
// no reverse proxy in front of it — see RateLimitPolicy's doc).
func clientIPFromHeader(xff string) string {
	first, _, _ := strings.Cut(xff, ",")
	return strings.TrimSpace(first)
}
