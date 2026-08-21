package internalapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/queue"
	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/webhook"
)

// RateLimiter is the shared token-bucket contract this package's
// ratelimit.allow operation wraps — the same single-method shape
// internal/platform/smtp.RateLimiter and internal/ratelimit.PostgresLimiter
// already share, redeclared here (not imported from either) so this
// package doesn't take a dependency on a specific consumer's package for
// what's structurally just one method.
type RateLimiter interface {
	Allow(ctx context.Context, key string, capacity, refillPerSecond float64) (bool, error)
}

// roleScopes is the least-privilege table this package exists to enforce —
// the HTTP-layer equivalent of deploy/postgres/roles.sql's per-role SQL
// GRANTs. Derived directly from grepping every s.cfg.Directory/.Store/
// .Queue/.RateLimiter/.Webhooks call site in internal/platform/smtp and
// internal/platform/imap's session handlers (wire.go's package doc has the
// full accounting) — not a speculative "roles might need this later" list.
var roleScopes = map[string]map[string]bool{
	RoleSMTPInbound: set(ScopeDirectoryVhost, ScopeStoreWrite, ScopeRateLimitAllow, ScopeWebhookEnqueue),
	RoleSMTPSubmission: set(
		ScopeDirectoryVhost, ScopeDirectoryAuthenticate, ScopeStoreWrite, ScopeQueueEnqueue, ScopeRateLimitAllow,
	),
	RoleIMAP: set(ScopeDirectoryAuthenticate, ScopeStoreRead, ScopeStoreList, ScopeStoreUpdateFlags),
}

func set(scopes ...string) map[string]bool {
	m := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		m[s] = true
	}
	return m
}

// Server implements the eight-operation internal API wire.go documents,
// backed by the same real Directory/Store/Queue/RateLimiter/Enqueuer the
// api role's process already constructs for its own management-API
// purposes (cmd/envelope/main.go passes the identical instances into both).
type Server struct {
	dir      directory.Directory
	store    storage.Store
	queue    queue.Backend
	limiter  RateLimiter
	webhooks webhook.Enqueuer

	// tokens maps a valid bearer token to the role identifier it
	// authenticates as (RoleSMTPInbound, etc.) — see NewServer's doc for
	// why this is keyed by token value, not by role.
	tokens map[string]string
}

// NewServer returns a Server. tokens maps each role's shared secret
// (cmd/envelope/main.go's ENVELOPE_INTERNAL_TOKEN_<ROLE>) to that role's
// identifier — a role with no token configured simply has no entry, so
// every request claiming that role is rejected (fail-closed, the same
// posture ENVELOPE_MASTER_KEY takes: silently accepting an unconfigured
// role would mean silently granting no one access, which is safe, but
// silently *generating* a token nobody set would mean whichever process
// asked first winning a value no other process could ever independently
// derive — not viable for a secret that must be identical across
// independently started processes).
func NewServer(dir directory.Directory, store storage.Store, q queue.Backend, limiter RateLimiter, webhooks webhook.Enqueuer, tokens map[string]string) *Server {
	return &Server{dir: dir, store: store, queue: q, limiter: limiter, webhooks: webhooks, tokens: tokens}
}

// Handler returns the internal API's http.Handler. Deliberately a plain
// net/http ServeMux, not a Goose module/router: this is a small,
// fixed, internal-only protocol (wire.go's eight operations), not a
// growing public REST surface — internal/api's Goose-module machinery
// (DI-injected controllers, DTO binding) is the right tool for that shape,
// not this one.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/v1/directory/vhost", s.authorize(ScopeDirectoryVhost, s.handleVhost))
	mux.HandleFunc("POST /internal/v1/directory/authenticate", s.authorize(ScopeDirectoryAuthenticate, s.handleAuthenticate))
	mux.HandleFunc("POST /internal/v1/store/write", s.authorize(ScopeStoreWrite, s.handleStoreWrite))
	mux.HandleFunc("GET /internal/v1/store/read", s.authorize(ScopeStoreRead, s.handleStoreRead))
	mux.HandleFunc("POST /internal/v1/store/list", s.authorize(ScopeStoreList, s.handleStoreList))
	mux.HandleFunc("POST /internal/v1/store/updateflags", s.authorize(ScopeStoreUpdateFlags, s.handleStoreUpdateFlags))
	mux.HandleFunc("POST /internal/v1/queue/enqueue", s.authorize(ScopeQueueEnqueue, s.handleQueueEnqueue))
	mux.HandleFunc("POST /internal/v1/ratelimit/allow", s.authorize(ScopeRateLimitAllow, s.handleRateLimitAllow))
	mux.HandleFunc("POST /internal/v1/webhook/enqueue", s.authorize(ScopeWebhookEnqueue, s.handleWebhookEnqueue))
	return mux
}

// authorize wraps next so it only runs for a request bearing a token that
// (a) exists in s.tokens and (b) whose role is granted requiredScope in
// roleScopes — the two checks together are this package's whole security
// property: a stolen smtp-inbound token can Write a message but a request
// to /queue/enqueue with that same token 403s, exactly as if smtp-inbound
// had never been granted a queue_jobs SQL grant at all.
func (s *Server) authorize(requiredScope string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get(HeaderToken)
		if token == "" {
			writeError(w, http.StatusUnauthorized, errors.New("internalapi: missing "+HeaderToken))
			return
		}

		role := ""
		for candidate, roleForToken := range s.tokens {
			if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
				role = roleForToken
				break
			}
		}
		if role == "" {
			writeError(w, http.StatusUnauthorized, errors.New("internalapi: token not recognized"))
			return
		}
		if !roleScopes[role][requiredScope] {
			writeError(w, http.StatusForbidden, errors.New("internalapi: role "+role+" is not granted "+requiredScope))
			return
		}

		next(w, r)
	}
}

func (s *Server) handleVhost(w http.ResponseWriter, r *http.Request) {
	var req vhostRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	v, ok := s.dir.Vhost(r.Context(), req.Domain)
	if !ok {
		writeJSON(w, http.StatusOK, vhostResponse{Found: false})
		return
	}

	dto := &vhostDTO{
		ID: v.ID, Domain: v.Domain, Active: v.Active, DKIMSelector: v.DKIMSelector,
		MaxMessageBytes: v.MaxMessageBytes, DailyQuota: v.DailyQuota,
		SpamRejectThreshold: v.SpamRejectThreshold, SpamQuarantineThreshold: v.SpamQuarantineThreshold,
		RetentionDays: v.RetentionDays,
	}
	if v.DKIMKey != nil {
		dto.DKIMKeyPEM = rsaKeyToPEM(v.DKIMKey)
	}
	writeJSON(w, http.StatusOK, vhostResponse{Found: true, Vhost: dto})
}

func (s *Server) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	var req authenticateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ok := s.dir.Authenticate(r.Context(), req.Vhost, req.LocalPart, req.Password)
	writeJSON(w, http.StatusOK, authenticateResponse{OK: ok})
}

func (s *Server) handleStoreWrite(w http.ResponseWriter, r *http.Request) {
	vhost, mailbox := r.URL.Query().Get("vhost"), r.URL.Query().Get("mailbox")
	if vhost == "" || mailbox == "" {
		writeError(w, http.StatusBadRequest, errors.New("internalapi: vhost and mailbox query params are required"))
		return
	}

	ref, err := s.store.Write(r.Context(), vhost, mailbox, r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, writeResponse{Vhost: ref.Vhost, Mailbox: ref.Mailbox, Key: ref.Key})
}

func (s *Server) handleStoreRead(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ref := storage.MessageRef{Vhost: q.Get("vhost"), Mailbox: q.Get("mailbox"), Key: q.Get("key")}
	if ref.Vhost == "" || ref.Mailbox == "" || ref.Key == "" {
		writeError(w, http.StatusBadRequest, errors.New("internalapi: vhost, mailbox, and key query params are required"))
		return
	}

	rc, err := s.store.Read(r.Context(), ref)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, rc)
}

func (s *Server) handleStoreList(w http.ResponseWriter, r *http.Request) {
	var req listRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	metas, err := s.store.List(r.Context(), req.Vhost, req.Mailbox)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	out := make([]messageMetaDTO, len(metas))
	for i, m := range metas {
		out[i] = messageMetaDTO{
			Vhost: m.Ref.Vhost, Mailbox: m.Ref.Mailbox, Key: m.Ref.Key,
			Size: m.Size, Flags: m.Flags, CreatedAt: m.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, listResponse{Metas: out})
}

func (s *Server) handleStoreUpdateFlags(w http.ResponseWriter, r *http.Request) {
	var req updateFlagsRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ref := storage.MessageRef{Vhost: req.Vhost, Mailbox: req.Mailbox, Key: req.Key}
	if err := s.store.UpdateFlags(r.Context(), ref, req.Flags); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleQueueEnqueue(w http.ResponseWriter, r *http.Request) {
	var req enqueueJobRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	job := queue.Job{
		ID: req.ID, Vhost: req.Vhost, From: req.From, To: req.To, BodyRef: req.BodyRef,
		NextAttemptAt: req.NextAttemptAt, CorrelationID: req.CorrelationID,
	}
	if err := s.queue.Enqueue(r.Context(), job); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRateLimitAllow(w http.ResponseWriter, r *http.Request) {
	var req rateLimitAllowRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	allowed, err := s.limiter.Allow(r.Context(), req.Key, req.Capacity, req.RefillPerSecond)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rateLimitAllowResponse{Allowed: allowed})
}

func (s *Server) handleWebhookEnqueue(w http.ResponseWriter, r *http.Request) {
	var req webhookEnqueueRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.webhooks.Enqueue(r.Context(), req.Vhost, req.EventType, req.Payload); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, errorResponse{Error: err.Error()})
}
