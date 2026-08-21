// Package webhook implements signed, retried webhook dispatch for the
// message lifecycle (TRD FR-6.x).
package webhook

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Store's lookup methods when no matching
// subscription exists (including when it belongs to a different vhost than
// the one asked for — FR-1.5).
var ErrNotFound = errors.New("webhook: not found")

// Subscription is a tenant's registered webhook endpoint (FR-6.5).
type Subscription struct {
	ID         string
	Vhost      string
	URL        string
	Secret     string
	EventTypes []string
	Disabled   bool
}

// DeliveryAttempt records one attempt to deliver an event to a
// Subscription, kept for the dead-letter visibility FR-6.4 requires. Vhost
// is denormalized from the originating Subscription (rather than requiring
// a join to look it up) so ListAttempts can enforce FR-1.5's mandatory
// vhost predicate directly against this table.
type DeliveryAttempt struct {
	// ID addresses this specific attempt row — needed for
	// ListAttemptsPage's cursor (FR-5.4), which a bare EventID/Attempt pair
	// can't serve as, since Redrive can create more than one attempt row
	// per (subscription, event) pair with no other unique-and-orderable
	// field between them.
	ID             string
	Vhost          string
	SubscriptionID string
	EventID        string
	Attempt        int
	StatusCode     int
	Error          string
	AttemptedAt    time.Time
	// Payload/EventType are the event's own body/type, recorded on every
	// attempt (not just the first) so Dispatcher.Redrive can rebuild a
	// fresh DeliveryJob for a dead-lettered event without needing the
	// original DeliveryJob row, which EventQueue.Complete already removed
	// by the time an operator asks for a manual redrive (docs/RUNBOOK.md
	// §4.3).
	Payload   []byte
	EventType string
}

// Store is the webhook subscription + delivery-history contract (FR-6.5).
// Phase 1 ships only an in-memory implementation (NewMemoryStore) so
// Phase 2 can compile against the real contract; Phase 3 replaces it with
// one backed by Goose's sql module without changing this interface.
type Store interface {
	// CreateSubscription registers a new subscription.
	CreateSubscription(ctx context.Context, sub Subscription) error

	// ListSubscriptions returns every one of vhost's subscriptions,
	// unbounded, including disabled ones (callers filter on Disabled as
	// needed). Kept unbounded rather than replaced by
	// ListSubscriptionsPage: Dispatcher.Enqueue must fan an event out to
	// every matching subscription, not just one page of them, and
	// DataController.Export needs every subscription for a complete GDPR
	// export (NFR-COMP-2) — silently truncating either to one page would be
	// a correctness bug, not just a UX gap the way an unpaginated admin
	// listing endpoint is.
	ListSubscriptions(ctx context.Context, vhost string) ([]Subscription, error)

	// ListSubscriptionsPage returns up to limit of vhost's subscriptions
	// (FR-5.4), cursor-paginated the same way directory.Service.ListVhosts
	// is — see that method's doc for the pattern, and ListSubscriptions's
	// doc for why that method stays unbounded instead of being replaced by
	// this one. WebhookController.ListSubscriptions (the API handler) calls
	// this.
	ListSubscriptionsPage(ctx context.Context, vhost, cursor string, limit int) ([]Subscription, error)

	// DisableSubscription soft-disables a subscription without deleting it,
	// preserving its delivery history (FR-6.5). vhost is a mandatory
	// predicate (FR-1.5): disabling id under the wrong vhost fails exactly
	// as if id didn't exist, rather than reaching across tenants.
	DisableSubscription(ctx context.Context, vhost, id string) error

	// RecordAttempt appends a delivery attempt to a subscription's history.
	RecordAttempt(ctx context.Context, attempt DeliveryAttempt) error

	// ListAttempts returns a subscription's full delivery attempt history,
	// unbounded, oldest first (FR-6.4's dead-letter visibility via the
	// API). vhost is a mandatory predicate (FR-1.5), the same as
	// DisableSubscription. Kept unbounded rather than replaced by
	// ListAttemptsPage: Dispatcher.Redrive scans every attempt for a
	// matching event ID to find the most recent one, which a single page
	// could miss for an event retried more times than one page holds.
	ListAttempts(ctx context.Context, vhost, subscriptionID string) ([]DeliveryAttempt, error)

	// ListAttemptsPage returns up to limit of subscriptionID's delivery
	// attempts (FR-5.4), oldest first, cursor-paginated the same way
	// directory.Service.ListVhosts is — see that method's doc for the
	// pattern, and ListAttempts's doc for why that method stays unbounded
	// instead of being replaced by this one. WebhookController.ListAttempts
	// (the API handler) calls this.
	ListAttemptsPage(ctx context.Context, vhost, subscriptionID, cursor string, limit int) ([]DeliveryAttempt, error)
}
