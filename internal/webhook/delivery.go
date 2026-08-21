package webhook

import (
	"context"
	"time"
)

// DeliveryJob is one pending HTTP delivery of an event to a single
// subscription (TRD FR-6.3/6.4). URL and Secret are snapshotted from the
// Subscription at Dispatcher.Enqueue time rather than looked up again at
// delivery time, so a subscription edited or disabled mid-retry doesn't
// change the outcome of deliveries already in flight for it.
type DeliveryJob struct {
	ID             string
	Vhost          string
	SubscriptionID string
	URL            string
	Secret         string
	EventID        string
	EventType      string
	Payload        []byte
	Attempts       int
	NextAttemptAt  time.Time
	LastError      string
	// CorrelationID carries NFR-OBS-2's log correlation ID across the
	// enqueuing role's process boundary into Dispatcher.Run's background
	// loop (possibly a different replica entirely) — set by
	// Dispatcher.Enqueue from its caller's ctx, re-attached by deliverOne
	// so a webhook delivery's logs still carry the same ID as the inbound
	// message or outbound job that triggered it.
	CorrelationID string
}

// EventQueue is the durable, retried webhook-delivery queue (FR-6.3: the
// HTTP POST itself only ever happens from Dispatcher.Run's background loop,
// never on the caller of Enqueue's goroutine, so a slow or unreachable
// tenant endpoint can't block mail acceptance or an API response).
// Deliberately the same shape as queue.Backend — both are durable,
// FOR-UPDATE-SKIP-LOCKED-claimed retry queues — but kept as a separate type
// since a webhook delivery (subscription/event/payload) and an outbound
// mail job (vhost/from/to/body ref) are different domains that happen to
// share a retry-queue shape.
type EventQueue interface {
	// Enqueue durably persists job and makes it eligible for Dequeue once
	// its NextAttemptAt has passed.
	Enqueue(ctx context.Context, job DeliveryJob) error

	// Dequeue claims and returns the next due job, if any. ok is false
	// when no job is currently due.
	Dequeue(ctx context.Context) (job DeliveryJob, ok bool, err error)

	// Complete marks a claimed job as delivered (or dead-lettered — see
	// Dispatcher.Run) and removes it from the queue. The job's delivery
	// history survives in Store's DeliveryAttempt rows regardless (FR-6.4).
	Complete(ctx context.Context, id string) error

	// Fail records a failed delivery attempt and reschedules the job for
	// nextAttemptAt (FR-3.4's backoff algorithm decides that time).
	Fail(ctx context.Context, id string, cause error, nextAttemptAt time.Time) error
}
