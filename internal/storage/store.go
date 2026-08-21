// Package storage defines the pluggable message-storage contract (TRD FR-4.x).
// All message read/write paths go through Store so no caller outside a
// backend implementation file holds backend-specific assumptions (FR-4.1).
package storage

import (
	"context"
	"io"
	"time"
)

// Standard IMAP system flags (RFC 3501 §2.3.2) — the flag vocabulary every
// Store implementation accepts from UpdateFlags. Kept backend-agnostic so
// IMAP (FR-7.3) and the API share one flag namespace regardless of which
// backend is configured.
const (
	FlagSeen     = "\\Seen"
	FlagAnswered = "\\Answered"
	FlagFlagged  = "\\Flagged"
	FlagDeleted  = "\\Deleted"
	FlagDraft    = "\\Draft"
)

// OutboxMailbox is the mailbox name submission mode (internal/platform/smtp)
// stages DKIM-signed outbound bodies under before enqueueing a delivery job
// (queue.Job.BodyRef points at a message here); internal/deliverer reads
// from the same location to actually send it (FR-3.x). Defined here rather
// than in either of those packages so neither has to import the other just
// for this one shared naming convention.
const OutboxMailbox = "Outbox"

// MessageRef identifies a stored message: which vhost, which mailbox (e.g.
// "INBOX" or the FR-2.5 quarantine mailbox), and the backend-assigned key.
type MessageRef struct {
	Vhost   string
	Mailbox string
	Key     string
}

// MessageMeta is a stored message's metadata, as returned by List/ListVhost.
type MessageMeta struct {
	Ref   MessageRef
	Size  int64
	Flags []string
	// CreatedAt is when the message was written (Postgres: the row's
	// sql.BaseEntity timestamp; maildir: the delivered file's mtime, which
	// Write never touches again after delivery). NFR-COMP-1's retention
	// purge and NFR-COMP-2's data export both need this to know a
	// message's age/provenance; List/ListVhost's original callers
	// (IMAP listing, the API's message-list surface) simply ignore it.
	CreatedAt time.Time
}

// Store is the pluggable message-storage contract (FR-4.1). Implementations
// exist per backend (maildir today; S3 and Postgres per FR-4.3/4.4 land in
// later phases) and must be swappable via config alone (FR-4.5).
type Store interface {
	// Write persists a new message body under vhost/mailbox and returns the
	// ref by which it can be read, listed, or mutated later.
	Write(ctx context.Context, vhost, mailbox string, body io.Reader) (MessageRef, error)

	// Read opens a stored message body. Callers must Close the result.
	Read(ctx context.Context, ref MessageRef) (io.ReadCloser, error)

	// List enumerates messages in a mailbox.
	List(ctx context.Context, vhost, mailbox string) ([]MessageMeta, error)

	// ListVhost enumerates every message stored for vhost, across every
	// mailbox/folder — unlike List, which only sees one named mailbox at a
	// time. NFR-COMP-1's retention purge and NFR-COMP-2's data export both
	// need "everything for this tenant," not "everything in one mailbox."
	ListVhost(ctx context.Context, vhost string) ([]MessageMeta, error)

	// UpdateFlags mutates a message's flags. This is the single path IMAP
	// (FR-7.3) and the API both go through, keeping backends consistent
	// regardless of access path.
	UpdateFlags(ctx context.Context, ref MessageRef, flags []string) error

	// Delete removes a stored message (used by the NFR-COMP-1 retention purge).
	Delete(ctx context.Context, ref MessageRef) error
}
