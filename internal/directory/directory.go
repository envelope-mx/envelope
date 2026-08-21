// Package directory manages vhosts, mailboxes, and DKIM keys (TRD FR-1.x).
//
// The production implementation (Service, in this package) is
// Postgres-backed, built directly on *gorm.DB rather than Goose's
// sql.Entity[T]/Query helpers: those types' query/log fields are
// unexported and only ever populated through Goose's DI container during
// module traversal, but internal/platform/smtp and internal/platform/imap
// are custom Goose platforms whose Boot(container) never traverses a
// module tree (TRD §2.1) — there's nothing to inject into. Service embeds
// sql.BaseEntity on its row types (TRD §7) and uses the same GORM+Postgres
// foundation the sql module wraps, just without the DI-bound convenience
// layer on top. internal/directory/memory is a non-durable stand-in for
// tests that don't need a real database.
package directory

import (
	"context"
	"crypto/rsa"
	"errors"
	"strings"
	"time"
)

// ErrNotFound is returned by Service's lookup methods when no matching
// row exists.
var ErrNotFound = errors.New("directory: not found")

// Directory is the read/auth surface internal/platform/smtp and
// internal/platform/imap depend on — deliberately smaller than Service's
// full CRUD surface, so both Service (Postgres) and memory.Directory
// satisfy it.
type Directory interface {
	// Vhost returns domain's Vhost, if registered.
	Vhost(ctx context.Context, domain string) (Vhost, bool)
	// VhostActive reports whether domain is a registered, active vhost
	// (FR-2.2's Directory check before accepting RCPT TO).
	VhostActive(ctx context.Context, domain string) bool
	// Authenticate reports whether password matches localPart@vhost's
	// stored credential. Used by both submission (FR-3.1) and IMAP
	// (FR-7.2) — the same credential store backs both access paths.
	Authenticate(ctx context.Context, vhost, localPart, password string) bool
}

// DefaultDKIMSelector is the DKIM selector assigned to every vhost added
// via Service.CreateVhost, until FR-1.2's per-vhost selector configuration
// is exposed through the API.
const DefaultDKIMSelector = "envelope"

// Account is a business/tenant that owns one or more Vhosts (1 Account : N
// Vhosts) — the unit API tokens are scoped to (see internal/apiauth), so a
// business managing several domains does so under one credential instead
// of a separate token per vhost.
type Account struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// Vhost is a hosted email domain (TRD §11 glossary) and its FR-1.2 policy.
type Vhost struct {
	ID           string
	AccountID    string // owning Account's ID
	Domain       string
	Active       bool
	DKIMSelector string
	DKIMKey      *rsa.PrivateKey

	// FR-1.2 per-vhost policy. Stored and returned from Phase 3; enforced
	// starting Phase 4 (message-size / spam-verdict handling).
	MaxMessageBytes         int64
	DailyQuota              int
	SpamRejectThreshold     float64
	SpamQuarantineThreshold float64
	// RetentionDays is NFR-COMP-1's per-vhost retention window (days);
	// <= 0 means "use internal/retention.Purger's platform default".
	RetentionDays int
}

// VhostPolicy is the FR-1.2/NFR-COMP-1 configurable policy fields on a
// vhost, as a standalone type so Service.UpdateVhostPolicy can take "the
// policy to set" without also accepting (and risking overwriting) Vhost's
// identity/DKIM fields.
type VhostPolicy struct {
	MaxMessageBytes         int64
	DailyQuota              int
	SpamRejectThreshold     float64
	SpamQuarantineThreshold float64
	RetentionDays           int
}

// Mailbox is a single account's credential (data model §7 `mailboxes`).
type Mailbox struct {
	ID           string
	VhostID      string
	LocalPart    string
	PasswordHash string
}

// ParseAddress splits an "alice@example.com" address into local part and
// domain. ok is false if addr has no "@".
func ParseAddress(addr string) (localPart, domain string, ok bool) {
	local, dom, found := strings.Cut(addr, "@")
	if !found || local == "" || dom == "" {
		return "", "", false
	}
	return local, dom, true
}

// MailboxPath returns the storage.Store mailbox-namespace path for
// localPart's folder: storage.Store's (vhost, mailbox) pair only has two
// levels, so per-account folders are nested into the second level as
// "{localPart}/{folder}" (e.g. "alice/INBOX"), keeping every account's
// mail under its own maildir subtree without changing the Store interface.
func MailboxPath(localPart, folder string) string {
	return localPart + "/" + folder
}
