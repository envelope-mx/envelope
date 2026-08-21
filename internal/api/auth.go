package api

import (
	"context"
	"errors"
	"strings"

	"github.com/awesome-goose/goose/io/output"
	"github.com/awesome-goose/goose/types"

	"github.com/envelope-mx/envelope/internal/apiauth"
	"github.com/envelope-mx/envelope/internal/audit"
	"github.com/envelope-mx/envelope/internal/directory"
)

// AdminToken is the bootstrap credential (ENVELOPE_API_ADMIN_TOKEN, wired
// in cmd/envelope/main.go) that authorizes against every account. FR-5.2
// requires every request be authenticated, but a token Store can't
// bootstrap itself — minting the very first scoped token requires already
// being authenticated as something, so one operator-controlled credential
// has to exist outside the Store. Once bootstrapped, an operator uses the
// admin token to create Accounts (AccountController), which auto-issues
// each account's first token; day-to-day API traffic uses those, not the
// admin token.
//
// A one-field struct, not a bare string: Goose's DI container
// (core/container.go's create) only ever populates inject:"" fields that
// are a pointer-to-struct or an interface — a plain named-string field is
// silently skipped (left at its zero value) with no error, which is
// exactly the bug this shape avoids. Every other injected dependency in
// this package (*directory.Service, webhook.Store, apiauth.Store) already
// satisfies one of those two shapes; this is the same fix applied to a
// value that would otherwise be a bare string.
type AdminToken struct {
	Value string
}

// authContext is what a successful authenticate call resolves a bearer
// token to.
type authContext struct {
	IsAdmin   bool
	AccountID string // meaningless when IsAdmin is true
}

// Actor renders the identity for audit.Entry.Actor (NFR-COMP-4): "admin"
// for the bootstrap credential, or "account:<id>" for an account-scoped
// token — enough to answer "who did this" without storing the token
// itself.
func (ac authContext) Actor() string {
	if ac.IsAdmin {
		return "admin"
	}
	return "account:" + ac.AccountID
}

// authenticate applies NFR-SEC-4's per-IP rate limit first (see
// RateLimitPolicy's doc — a 429 short-circuits before any token lookup, so
// an attacker hammering the API with credential guesses is slowed down
// regardless of whether any guess would ever succeed), then extracts a
// bearer token from the raw Authorization header value and resolves it to
// an authContext, or a 401 Output if the header is missing/malformed or the
// token doesn't match anything live.
func authenticate(ctx context.Context, tokens apiauth.Store, admin *AdminToken, limiter *RateLimitPolicy, header, clientIPHeader string) (authContext, types.Output) {
	if errOut := checkAPIRateLimit(ctx, limiter, clientIPHeader); errOut != nil {
		return authContext{}, errOut
	}

	raw, ok := bearerToken(header)
	if !ok {
		return authContext{}, output.Unauthorized("missing or malformed Authorization header (expected: Bearer <token>)")
	}

	if admin != nil && admin.Value != "" && apiauth.ConstantTimeEqual(raw, admin.Value) {
		return authContext{IsAdmin: true}, nil
	}

	tok, found, err := tokens.Authenticate(ctx, apiauth.HashToken(raw))
	if err != nil {
		return authContext{}, output.InternalServerError("failed to authenticate")
	}
	if !found {
		return authContext{}, output.Unauthorized("invalid or revoked token")
	}
	return authContext{AccountID: tok.AccountID}, nil
}

// checkAPIRateLimit is NFR-SEC-4: a 429 if clientIPHeader (X-Forwarded-For)
// resolves to an address that has exhausted policy's token bucket. A nil
// policy, a nil policy.Limiter, or an empty/unresolvable clientIPHeader all
// no-op (see RateLimitPolicy's doc for why each of those is a legitimate,
// not-a-bug state) rather than blocking the request.
func checkAPIRateLimit(ctx context.Context, policy *RateLimitPolicy, clientIPHeader string) types.Output {
	if policy == nil || policy.Limiter == nil {
		return nil
	}
	ip := clientIPFromHeader(clientIPHeader)
	if ip == "" {
		return nil
	}

	capacity := policy.Capacity
	if capacity <= 0 {
		capacity = DefaultAPIRateLimitCapacity
	}
	refill := policy.RefillPerSecond
	if refill <= 0 {
		refill = DefaultAPIRateLimitRefillPerSecond
	}

	allowed, err := policy.Limiter.Allow(ctx, "api:"+ip, capacity, refill)
	if err == nil && !allowed {
		return output.TooManyRequests("rate limit exceeded, try again later")
	}
	return nil
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return raw, raw != ""
}

// requireAdmin authenticates header and requires the admin identity — for
// platform-level operations (vhost creation, listing every tenant) no
// per-vhost token could ever be legitimately authorized for. The returned
// authContext is only meaningful when errOut is nil; callers use it to
// attribute an audit.Entry to the resolved identity.
func requireAdmin(ctx context.Context, tokens apiauth.Store, admin *AdminToken, limiter *RateLimitPolicy, header, clientIPHeader string) (authContext, types.Output) {
	ac, errOut := authenticate(ctx, tokens, admin, limiter, header, clientIPHeader)
	if errOut != nil {
		return authContext{}, errOut
	}
	if !ac.IsAdmin {
		return authContext{}, output.Forbidden("admin token required")
	}
	return ac, nil
}

// requireAccountAccess authenticates header and requires either the admin
// identity or a token scoped to accountID (FR-5.2: "authorized against the
// account(s) the caller's token is scoped to"). A pure string compare, no
// DB lookup — used for genuinely account-level operations (token CRUD,
// self-serve vhost creation, account CRUD). See requireAdmin's doc on the
// returned authContext.
func requireAccountAccess(ctx context.Context, tokens apiauth.Store, admin *AdminToken, limiter *RateLimitPolicy, header, clientIPHeader, accountID string) (authContext, types.Output) {
	ac, errOut := authenticate(ctx, tokens, admin, limiter, header, clientIPHeader)
	if errOut != nil {
		return authContext{}, errOut
	}
	if ac.IsAdmin || ac.AccountID == accountID {
		return ac, nil
	}
	return authContext{}, output.Forbidden("token is not authorized for this account")
}

// requireVhostAccountAccess authenticates header and requires either the
// admin identity or a token whose account owns vhostID — for the routes
// still nested under /vhosts/:vhostId/... (mailbox/webhook/audit/data
// operations) where a token's account isn't the vhost ID itself, so
// resolving ownership needs an extra lookup requireAccountAccess never
// needed.
//
// Any lookup failure (vhostID doesn't exist at all) and any ownership
// mismatch (a real vhost belonging to a different account) both return the
// identical 403 below, deliberately not a distinguishable 404: the old
// requireVhostAccess was a pure string compare with zero DB lookups, so a
// non-admin caller learned nothing by probing a vhost ID. A naive
// 404-vs-403 split here would introduce a new cross-tenant existence
// oracle — any authenticated account could enumerate which vhost IDs exist
// across every other tenant just by which status code comes back. Admin
// callers are unaffected either way: they skip this check entirely and get
// their own 404 from the controller's subsequent GetVhost call, same as
// today.
func requireVhostAccountAccess(ctx context.Context, dir *directory.Service, tokens apiauth.Store, admin *AdminToken, limiter *RateLimitPolicy, header, clientIPHeader, vhostID string) (authContext, types.Output) {
	ac, errOut := authenticate(ctx, tokens, admin, limiter, header, clientIPHeader)
	if errOut != nil {
		return authContext{}, errOut
	}
	if ac.IsAdmin {
		return ac, nil
	}

	v, err := dir.GetVhost(ctx, vhostID)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return authContext{}, output.Forbidden("token is not authorized for this vhost")
		}
		return authContext{}, output.InternalServerError("failed to verify vhost")
	}
	if ac.AccountID == v.AccountID {
		return ac, nil
	}
	return authContext{}, output.Forbidden("token is not authorized for this vhost")
}

// recordAudit appends an NFR-COMP-4 entry after a mutation has already
// succeeded. Errors are deliberately swallowed (best-effort, matching
// this package's other fire-and-forget writes like webhook Enqueue calls)
// rather than failing the whole request: a response the caller already
// received success for shouldn't flip to an error because the audit
// write itself hiccuped.
func recordAudit(ctx context.Context, store audit.Store, ac authContext, action, target, detail string) {
	if store == nil {
		return
	}
	_ = store.Record(ctx, audit.Entry{Actor: ac.Actor(), Action: action, Target: target, Detail: detail})
}
