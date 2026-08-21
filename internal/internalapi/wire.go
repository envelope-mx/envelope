// Package internalapi is NFR-SEC-5's fuller network-segmentation goal,
// closed for the SMTP-facing roles: "a compromise of the SMTP-facing
// process does not directly expose the DB credential store"
// (deploy/k8s/networkpolicy.yaml's own header comment named this as the
// gap deploy/postgres/roles.sql's per-role SQL grants alone couldn't
// close). smtp-inbound, smtp-submission, and imap no longer need to hold a
// live Postgres credential at all when each runs as its own process
// (Kubernetes's one-Deployment-per-role shape, the same precondition
// internal/db.DSNForRole already requires) — instead they call this
// package's Client types, which speak a small, purpose-built HTTP protocol
// to Server, bundled into the api role's process (the one that already
// holds the DB connection for its own management-API purposes).
//
// This is deliberately not a generic passthrough of directory.Directory/
// storage.Store/queue.Backend/webhook.Enqueuer's full method sets: the
// wire protocol below exposes exactly the eight operations
// internal/platform/smtp and internal/platform/imap's session handlers
// actually call (grep internal/platform/smtp/*.go internal/platform/imap/*.go
// for every s.cfg.Directory/.Store/.Queue/.RateLimiter/.Webhooks call site
// to verify — there is no ninth). Server additionally enforces which of
// those eight operations a given caller's token may use, matching
// deploy/postgres/roles.sql's own least-privilege philosophy at the SQL
// layer: smtp-inbound's token can Write a message but not Enqueue a queue
// job; imap's token can Read/List/UpdateFlags but not Write; and so on —
// see roleScopes in server.go for the exact table. Client, correspondingly,
// implements the full directory.Directory/storage.Store/queue.Backend
// interfaces (Go's type system requires every method, since
// smtp.Config.Directory/.Store/.Queue are typed as those interfaces, not a
// narrower one this package could define instead) but the methods outside
// the eight above return a clear, static "not exposed to SMTP-facing
// roles" error rather than a server round-trip that would always be
// denied — see client.go's unsupportedX methods.
package internalapi

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// Scope names Server's auth middleware checks a caller's token against
// (see roleScopes in server.go). Exported so main.go's role wiring and
// this package's own tests share one vocabulary instead of restating
// string literals.
const (
	ScopeDirectoryVhost        = "directory.vhost"
	ScopeDirectoryAuthenticate = "directory.authenticate"
	ScopeStoreWrite            = "store.write"
	ScopeStoreRead             = "store.read"
	ScopeStoreList             = "store.list"
	ScopeStoreUpdateFlags      = "store.updateflags"
	ScopeQueueEnqueue          = "queue.enqueue"
	ScopeRateLimitAllow        = "ratelimit.allow"
	ScopeWebhookEnqueue        = "webhook.enqueue"
)

// Role identifiers — must match cmd/envelope/main.go's
// roleSMTPInbound/roleSMTPSubmission/roleIMAP constants exactly (the same
// string-literal-as-shared-convention deploy/postgres/roles.sql's role-name
// suffixes and internal/db.DSNForRole already rely on, rather than an
// import between main and this package).
const (
	RoleSMTPInbound    = "smtp-inbound"
	RoleSMTPSubmission = "smtp-submission"
	RoleIMAP           = "imap"
)

// HeaderToken is the internal token's header — deliberately not
// "Authorization" (internal/api's public management-API header): these are
// a different credential class entirely (a process-to-process shared
// secret, not a tenant/admin bearer token), and using a distinct header
// name makes that impossible to confuse at a glance in logs or packet
// captures.
const HeaderToken = "X-Envelope-Internal-Token"

// errorResponse is every non-2xx response's JSON body.
type errorResponse struct {
	Error string `json:"error"`
}

// --- directory.vhost ---

type vhostRequest struct {
	Domain string `json:"domain"`
}

type vhostResponse struct {
	Found bool      `json:"found"`
	Vhost *vhostDTO `json:"vhost,omitempty"`
}

// vhostDTO carries directory.Vhost over the wire, PEM-encoding DKIMKey
// (encodeRSAKeyPEM/decodeRSAKeyPEM below) — submission needs the actual
// private key material to DKIM-sign outbound mail (FR-3.2,
// submissionSession.Data), the same plaintext key
// internal/directory.Service.hydrateVhost already decrypts and hands back
// today over a direct DB connection. Moving that call across this
// package's HTTP boundary changes *where* the decrypt happens (still
// inside the api role's process, which is the only one holding
// ENVELOPE_MASTER_KEY) and *how* the plaintext key reaches the process
// that needs it to sign (this wire format instead of an in-process Go
// value) — it does not add a new place the plaintext key is ever exposed
// beyond what direct DB access already exposed to submission's process.
type vhostDTO struct {
	ID                      string  `json:"id"`
	Domain                  string  `json:"domain"`
	Active                  bool    `json:"active"`
	DKIMSelector            string  `json:"dkimSelector"`
	DKIMKeyPEM              string  `json:"dkimKeyPem,omitempty"`
	MaxMessageBytes         int64   `json:"maxMessageBytes"`
	DailyQuota              int     `json:"dailyQuota"`
	SpamRejectThreshold     float64 `json:"spamRejectThreshold"`
	SpamQuarantineThreshold float64 `json:"spamQuarantineThreshold"`
	RetentionDays           int     `json:"retentionDays"`
}

// --- directory.authenticate ---

type authenticateRequest struct {
	Vhost     string `json:"vhost"`
	LocalPart string `json:"localPart"`
	Password  string `json:"password"`
}

type authenticateResponse struct {
	OK bool `json:"ok"`
}

// --- store.write (raw body, metadata via query params — see client.go) ---

type writeResponse struct {
	Vhost   string `json:"vhost"`
	Mailbox string `json:"mailbox"`
	Key     string `json:"key"`
}

// --- store.read (raw body response, ref via query params) ---

// --- store.list ---

type listRequest struct {
	Vhost   string `json:"vhost"`
	Mailbox string `json:"mailbox"`
}

type listResponse struct {
	Metas []messageMetaDTO `json:"metas"`
}

type messageMetaDTO struct {
	Vhost     string    `json:"vhost"`
	Mailbox   string    `json:"mailbox"`
	Key       string    `json:"key"`
	Size      int64     `json:"size"`
	Flags     []string  `json:"flags"`
	CreatedAt time.Time `json:"createdAt"`
}

// --- store.updateflags ---

type updateFlagsRequest struct {
	Vhost   string   `json:"vhost"`
	Mailbox string   `json:"mailbox"`
	Key     string   `json:"key"`
	Flags   []string `json:"flags"`
}

// --- queue.enqueue ---

type enqueueJobRequest struct {
	ID            string    `json:"id"`
	Vhost         string    `json:"vhost"`
	From          string    `json:"from"`
	To            string    `json:"to"`
	BodyRef       string    `json:"bodyRef"`
	NextAttemptAt time.Time `json:"nextAttemptAt"`
	CorrelationID string    `json:"correlationId"`
}

// --- ratelimit.allow ---

type rateLimitAllowRequest struct {
	Key             string  `json:"key"`
	Capacity        float64 `json:"capacity"`
	RefillPerSecond float64 `json:"refillPerSecond"`
}

type rateLimitAllowResponse struct {
	Allowed bool `json:"allowed"`
}

// --- webhook.enqueue ---

type webhookEnqueueRequest struct {
	Vhost     string `json:"vhost"`
	EventType string `json:"eventType"`
	Payload   []byte `json:"payload"` // encoding/json base64-encodes []byte automatically
}

// rsaKeyToPEM/pemToRSAKey mirror internal/directory/service.go's
// identically-shaped unexported encodeRSAKeyPEM/decodeRSAKeyPEM (duplicated
// rather than exported from that package: this is vhostDTO's own
// wire-format concern, not something internal/directory's other callers
// should depend on).
func rsaKeyToPEM(key *rsa.PrivateKey) string {
	der := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

func pemToRSAKey(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("internalapi: no PEM block found in DKIM key material")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
