// Package audit implements NFR-COMP-4: an audit log for administrative
// actions (vhost create/deactivate, mailbox/webhook/token changes) — who,
// what, when, recorded independently of internal/api's response path so
// a bug in the caller's own error handling can't silently suppress an
// audit entry for an action that actually happened.
package audit

import (
	"context"
	"time"
)

// Entry is one recorded administrative action (TRD §7 audit_log: actor,
// action, target, before/after, at).
type Entry struct {
	ID     string
	Actor  string // "admin", or "vhost:<vhostID>" for a vhost-scoped token
	Action string // e.g. "vhost.create", "mailbox.delete"
	Target string // the affected resource's ID ("" for platform-level actions)
	Detail string // freeform context (e.g. the domain just created)
	At     time.Time
}

// DefaultPageSize/MaxPageSize bound ListPage (FR-5.4) — the same values and
// reasoning as directory.DefaultVhostPageSize/MaxVhostPageSize, just
// declared separately since this is a different package.
const (
	DefaultPageSize = 100
	MaxPageSize     = 500
)

// Store persists and retrieves audit entries.
type Store interface {
	// Record appends entry to the log. Entries are never updated or
	// deleted through this interface — an audit log that can be edited
	// after the fact isn't one.
	Record(ctx context.Context, entry Entry) error

	// List returns every entry affecting target (a vhost ID, typically),
	// unbounded, newest first. target "" returns platform-level entries
	// (vhost creation — the one action with no vhost yet to scope it to).
	// Kept unbounded rather than replaced by ListPage: DataController.Export
	// needs every entry for a complete GDPR export (NFR-COMP-2), where
	// silently truncating to one page would make the export lie about
	// being complete.
	List(ctx context.Context, target string) ([]Entry, error)

	// ListPage returns up to limit of target's entries (FR-5.4), newest
	// first, cursor-paginated the same way directory.Service.ListVhosts is
	// — see that method's doc for the pattern, and List's doc for why that
	// method stays unbounded instead of being replaced by this one.
	// AuditController.ListEntries (the API handler) calls this. cursor is
	// the ID of the last entry seen on the previous page.
	ListPage(ctx context.Context, target, cursor string, limit int) ([]Entry, error)
}
