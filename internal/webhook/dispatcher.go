package webhook

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/logging"
	"github.com/isaiahiroko/envelope/internal/metrics"
	"github.com/isaiahiroko/envelope/internal/queue"
)

// Enqueuer is the narrow surface callers on a request/connection-handling
// path need (FR-6.3): durably schedule an event for delivery without ever
// making the actual HTTP call themselves. internal/platform/smtp's inbound
// session and internal/deliverer both depend on this instead of *Dispatcher
// directly, so a fake can stand in without needing an HTTP server in tests
// that don't care about delivery itself.
type Enqueuer interface {
	Enqueue(ctx context.Context, vhost, eventType string, payload []byte) error
}

// Redriver is the narrow surface WebhookController needs to manually retry
// a dead-lettered delivery (docs/RUNBOOK.md §4.3's previously-missing
// "retry now" operation) — kept separate from Enqueuer/*Dispatcher the same
// way Enqueuer itself is kept separate from *Dispatcher: the API needs
// exactly this, not the ability to run Enqueue or the delivery loop.
type Redriver interface {
	Redrive(ctx context.Context, vhost, subscriptionID, eventID string) error
}

// DefaultBackoffBase/Max/MaxAttempts are Dispatcher's FR-3.4-style retry
// defaults for webhook delivery, mirroring the outbound mail deliverer's
// own defaults (internal/deliverer) since both are "retry an external
// endpoint with backoff, dead-letter after N attempts" problems.
const (
	DefaultBackoffBase = 30 * time.Second
	DefaultBackoffMax  = 30 * time.Minute
	DefaultMaxAttempts = 8
)

// Dispatcher is the async, retried webhook delivery engine (FR-6.1/6.3/6.4).
// Enqueue fans an event out to every matching, enabled subscription and
// returns as soon as those rows are durably persisted — the HTTP POST to a
// tenant's endpoint only ever happens later, from Run's background loop,
// so a slow or unreachable endpoint can never block whatever called
// Enqueue.
type Dispatcher struct {
	Store  Store
	Queue  EventQueue
	Client *http.Client

	BackoffBase, BackoffMax time.Duration
	MaxAttempts             int

	// PollInterval bounds how long Run sleeps between Dequeue attempts when
	// the queue is empty.
	PollInterval time.Duration

	mu   sync.Mutex
	rand *rand.Rand
}

// NewDispatcher returns a Dispatcher with FR-3.4-style defaults, backed by
// store and queue. Callers must run MigratePostgres (or
// internal/storage/migrations.All) first when queue is a PostgresEventQueue.
func NewDispatcher(store Store, queue EventQueue) *Dispatcher {
	return &Dispatcher{
		Store: store, Queue: queue,
		Client:       &http.Client{Timeout: 10 * time.Second},
		BackoffBase:  DefaultBackoffBase,
		BackoffMax:   DefaultBackoffMax,
		MaxAttempts:  DefaultMaxAttempts,
		PollInterval: time.Second,
		rand:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

var _ Enqueuer = (*Dispatcher)(nil)
var _ Redriver = (*Dispatcher)(nil)

// Enqueue durably schedules eventType/payload for delivery to every
// enabled subscription registered for vhost whose EventTypes either is
// empty (matches everything) or explicitly lists eventType (FR-6.5).
// Subscriptions that don't match are simply skipped — Enqueue never
// returns an error just because nothing was subscribed.
func (d *Dispatcher) Enqueue(ctx context.Context, vhost, eventType string, payload []byte) error {
	subs, err := d.Store.ListSubscriptions(ctx, vhost)
	if err != nil {
		return fmt.Errorf("webhook: enqueue %s for vhost %q: %w", eventType, vhost, err)
	}

	eventID := uuid.NewString()
	now := time.Now()
	// NFR-OBS-2: carry whatever correlation ID the caller's ctx already has
	// (set by inboundSession.Data or deliverer.handle) onto the durably
	// persisted job, so Run's background loop — possibly a different
	// process/replica by the time it actually claims this row — can
	// re-attach the same ID to its own logs (see deliverOne).
	correlationID := logging.CorrelationID(ctx)
	for _, sub := range subs {
		if sub.Disabled || !matchesEventType(sub, eventType) {
			continue
		}
		job := DeliveryJob{
			ID:             uuid.NewString(),
			Vhost:          vhost,
			SubscriptionID: sub.ID,
			URL:            sub.URL,
			Secret:         sub.Secret,
			EventID:        eventID,
			EventType:      eventType,
			Payload:        payload,
			NextAttemptAt:  now,
			CorrelationID:  correlationID,
		}
		if err := d.Queue.Enqueue(ctx, job); err != nil {
			return fmt.Errorf("webhook: enqueue %s for subscription %q: %w", eventType, sub.ID, err)
		}
		slog.InfoContext(ctx, "webhook event enqueued",
			"vhost", vhost, "event_type", eventType, "event_id", eventID, "subscription_id", sub.ID)
	}
	return nil
}

// Redrive re-enqueues a fresh delivery attempt for (subscriptionID,
// eventID) against vhost, using its most recent recorded attempt's
// payload/event type (RecordAttempt persists both specifically so this is
// possible — see DeliveryAttempt's doc) and the subscription's *current*
// URL/secret rather than whatever they were at the original attempt's
// time, in case the tenant has since edited them. Closes
// docs/RUNBOOK.md §4.3's "a dead-lettered event has no retry now endpoint"
// gap. Returns ErrNotFound if subscriptionID doesn't belong to vhost, or if
// eventID was never attempted against it; returns a plain error if the
// subscription is disabled (there is nowhere to redrive to).
func (d *Dispatcher) Redrive(ctx context.Context, vhost, subscriptionID, eventID string) error {
	subs, err := d.Store.ListSubscriptions(ctx, vhost)
	if err != nil {
		return fmt.Errorf("webhook: redrive: list subscriptions: %w", err)
	}
	var sub Subscription
	found := false
	for _, s := range subs {
		if s.ID == subscriptionID {
			sub, found = s, true
			break
		}
	}
	if !found {
		return fmt.Errorf("webhook: redrive: subscription %q: %w", subscriptionID, ErrNotFound)
	}
	if sub.Disabled {
		return fmt.Errorf("webhook: redrive: subscription %q is disabled", subscriptionID)
	}

	attempts, err := d.Store.ListAttempts(ctx, vhost, subscriptionID)
	if err != nil {
		return fmt.Errorf("webhook: redrive: list attempts: %w", err)
	}
	var last DeliveryAttempt
	found = false
	for _, a := range attempts { // oldest-first; keep overwriting to land on the most recent match
		if a.EventID == eventID {
			last, found = a, true
		}
	}
	if !found {
		return fmt.Errorf("webhook: redrive: event %q was never attempted against subscription %q: %w",
			eventID, subscriptionID, ErrNotFound)
	}

	job := DeliveryJob{
		ID:             uuid.NewString(),
		Vhost:          vhost,
		SubscriptionID: sub.ID,
		URL:            sub.URL,
		Secret:         sub.Secret,
		EventID:        eventID,
		EventType:      last.EventType,
		Payload:        last.Payload,
		NextAttemptAt:  time.Now(),
		CorrelationID:  logging.CorrelationID(ctx),
	}
	if err := d.Queue.Enqueue(ctx, job); err != nil {
		return fmt.Errorf("webhook: redrive: enqueue: %w", err)
	}
	slog.InfoContext(ctx, "webhook delivery manually redriven",
		"vhost", vhost, "subscription_id", subscriptionID, "event_id", eventID)
	return nil
}

func matchesEventType(sub Subscription, eventType string) bool {
	if len(sub.EventTypes) == 0 {
		return true
	}
	for _, t := range sub.EventTypes {
		if t == eventType {
			return true
		}
	}
	return false
}

// Run polls Queue for due deliveries and attempts each one, blocking until
// ctx is cancelled (the same shape as internal/deliverer.Deliverer.Run —
// both are "drain a durable retry queue" background loops). Deliveries are
// dispatched concurrently, one goroutine per claimed job, so one slow
// tenant endpoint doesn't stall every other pending delivery.
func (d *Dispatcher) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		job, ok, err := d.Queue.Dequeue(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(d.PollInterval)
			continue
		}
		if !ok {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(d.PollInterval):
			}
			continue
		}

		wg.Add(1)
		go func(job DeliveryJob) {
			defer wg.Done()
			d.deliverOne(ctx, job)
		}(job)
	}
}

func (d *Dispatcher) deliverOne(ctx context.Context, job DeliveryJob) {
	// NFR-OBS-2: re-attach the correlation ID this job was enqueued with
	// (see Enqueue) so this delivery attempt's logs — potentially on a
	// different replica, potentially much later — still trace back to the
	// inbound message or outbound job that triggered it.
	ctx = logging.WithCorrelationID(ctx, job.CorrelationID)

	statusCode, sendErr := d.send(ctx, job)
	attempt := DeliveryAttempt{
		Vhost:          job.Vhost,
		SubscriptionID: job.SubscriptionID,
		EventID:        job.EventID,
		Attempt:        job.Attempts + 1,
		StatusCode:     statusCode,
		AttemptedAt:    time.Now(),
		// Recorded on every attempt, not just retained on the in-flight
		// job, so Redrive can rebuild a fresh DeliveryJob after this job's
		// row is gone (Complete deletes it on both success and dead-letter
		// — see DeliveryAttempt's doc).
		Payload:   job.Payload,
		EventType: job.EventType,
	}
	if sendErr != nil {
		attempt.Error = sendErr.Error()
		metrics.WebhookDeliveryFailuresTotal.Inc()
	}
	_ = d.Store.RecordAttempt(ctx, attempt)

	if sendErr == nil {
		slog.InfoContext(ctx, "webhook delivered",
			"vhost", job.Vhost, "subscription_id", job.SubscriptionID, "event_id", job.EventID,
			"attempt", job.Attempts+1, "status_code", statusCode)
		_ = d.Queue.Complete(ctx, job.ID)
		return
	}

	if job.Attempts+1 >= d.MaxAttempts {
		// Dead-lettered: removed from the active retry queue, but its full
		// attempt history remains queryable via Store.ListAttempts (FR-6.4).
		slog.WarnContext(ctx, "webhook delivery dead-lettered",
			"vhost", job.Vhost, "subscription_id", job.SubscriptionID, "event_id", job.EventID,
			"attempts", job.Attempts+1, "error", sendErr.Error())
		_ = d.Queue.Complete(ctx, job.ID)
		return
	}

	next := time.Now().Add(d.nextBackoff(job.Attempts))
	slog.WarnContext(ctx, "webhook delivery failed, retrying",
		"vhost", job.Vhost, "subscription_id", job.SubscriptionID, "event_id", job.EventID,
		"attempt", job.Attempts+1, "error", sendErr.Error(), "next_attempt_at", next)
	_ = d.Queue.Fail(ctx, job.ID, sendErr, next)
}

func (d *Dispatcher) nextBackoff(attempt int) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queue.FullJitter(attempt, d.BackoffBase, d.BackoffMax, d.rand)
}

// send performs the actual HTTP POST — the only part of delivery that can
// block on a slow/unreachable tenant endpoint, confined to Run's
// background goroutine per job (FR-6.3).
func (d *Dispatcher) send(ctx context.Context, job DeliveryJob) (statusCode int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, job.URL, bytes.NewReader(job.Payload))
	if err != nil {
		return 0, fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Envelope-Signature", Sign(job.Secret, job.Payload))
	req.Header.Set("X-Envelope-Event", job.EventType)

	resp, err := d.Client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("webhook: request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("webhook: endpoint returned status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
