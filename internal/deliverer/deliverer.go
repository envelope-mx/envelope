// Package deliverer is Envelope's outbound mail deliverer (TRD FR-3.x,
// M4): it drains internal/queue.Backend, resolves each job's recipient
// domain's MX hosts, and attempts real SMTP delivery to the remote MTA,
// with exponential-backoff retry, a per-destination-domain concurrency
// cap, DSN (bounce) generation, and message.delivered/bounced/deferred
// webhook events — the consumer internal/platform/smtp's submission mode
// has been enqueueing jobs for since Phase 2, with nothing to read them
// until now.
package deliverer

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/logging"
	"github.com/envelope-mx/envelope/internal/metrics"
	"github.com/envelope-mx/envelope/internal/queue"
	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/webhook"
)

// Defaults mirror internal/webhook.Dispatcher's — both are "retry an
// external endpoint with backoff, dead-letter/bounce after N attempts"
// problems, and TRD FR-3.4's backoff_max_secs doesn't prescribe different
// numbers for the two cases.
const (
	DefaultBackoffBase          = 30 * time.Second
	DefaultBackoffMax           = 30 * time.Minute
	DefaultMaxAttempts          = 8
	DefaultPerDomainConcurrency = 5 // FR-3.5
	DefaultPort                 = 25
	DefaultDialTimeout          = 30 * time.Second
	DefaultPollInterval         = time.Second
	// DefaultQueueDepthSampleInterval bounds how often Run refreshes
	// envelope_queue_depth (NFR-OBS-1).
	DefaultQueueDepthSampleInterval = 15 * time.Second
)

// Config configures a Deliverer.
type Config struct {
	Queue     queue.Backend
	Store     storage.Store
	Directory directory.Directory
	// Webhooks fires message.delivered/message.bounced/message.deferred
	// (FR-6.1/6.3). nil disables webhook firing entirely (e.g. tests that
	// don't care about it).
	Webhooks webhook.Enqueuer
	Resolver Resolver

	// Domain is the HELO/EHLO identity this deliverer announces to remote
	// MTAs, and the domain its generated DSNs' postmaster address uses.
	Domain string
	// Port is the remote SMTP port to connect to. Defaults to 25 (real MX
	// delivery); tests override it to point at a local loopback server.
	Port int

	BackoffBase, BackoffMax time.Duration // FR-3.4
	MaxAttempts             int           // bounds retries before DSN + dead-letter (FR-3.6)
	PerDomainConcurrency    int           // FR-3.5

	// PollInterval bounds how long Run sleeps between Dequeue attempts
	// when the queue is empty.
	PollInterval time.Duration
	// DialTimeout bounds how long connecting to one MX host may take.
	DialTimeout time.Duration
	// QueueDepthSampleInterval bounds how often Run refreshes
	// envelope_queue_depth.
	QueueDepthSampleInterval time.Duration
}

func (c Config) withDefaults() Config {
	if c.BackoffBase <= 0 {
		c.BackoffBase = DefaultBackoffBase
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = DefaultBackoffMax
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.PerDomainConcurrency <= 0 {
		c.PerDomainConcurrency = DefaultPerDomainConcurrency
	}
	if c.Port <= 0 {
		c.Port = DefaultPort
	}
	if c.PollInterval <= 0 {
		c.PollInterval = DefaultPollInterval
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.QueueDepthSampleInterval <= 0 {
		c.QueueDepthSampleInterval = DefaultQueueDepthSampleInterval
	}
	return c
}

// Deliverer drains Config.Queue and attempts real SMTP delivery for each
// job.
type Deliverer struct {
	cfg Config
	sem *domainSemaphores

	mu   sync.Mutex
	rand *rand.Rand
}

// New returns a Deliverer for cfg, filling in defaults for any zero-valued
// tuning field.
func New(cfg Config) *Deliverer {
	cfg = cfg.withDefaults()
	return &Deliverer{
		cfg:  cfg,
		sem:  newDomainSemaphores(cfg.PerDomainConcurrency),
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Run polls Config.Queue for due jobs and attempts each one, blocking
// until ctx is cancelled. Each claimed job is dispatched to its own
// goroutine, gated by a per-destination-domain semaphore (FR-3.5) so one
// congested destination can't starve delivery to every other destination.
func (d *Deliverer) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		d.sampleQueueDepth(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		job, ok, err := d.cfg.Queue.Dequeue(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(d.cfg.PollInterval)
			continue
		}
		if !ok {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(d.cfg.PollInterval):
			}
			continue
		}

		domain := destinationDomain(job.To)
		wg.Add(1)
		go func(job queue.Job, domain string) {
			defer wg.Done()
			release, err := d.sem.acquire(ctx, domain)
			if err != nil {
				// ctx was cancelled while waiting for a concurrency slot;
				// the job stays claimed and will be picked up again after
				// this process restarts (NFR-AV-2 durability, same as any
				// other in-flight-at-shutdown job).
				return
			}
			defer release()
			d.handle(ctx, job)
		}(job, domain)
	}
}

// sampleQueueDepth refreshes envelope_queue_depth on a timer until ctx is
// cancelled (NFR-OBS-1). A timer, not an inline increment/decrement at
// Enqueue/Complete/Fail, so the gauge can never drift from the queue's
// actual persisted count — a missed decrement due to a bug or a crash
// between operations would otherwise accumulate error forever.
func (d *Deliverer) sampleQueueDepth(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.QueueDepthSampleInterval)
	defer ticker.Stop()

	refresh := func() {
		count, err := d.cfg.Queue.Count(ctx)
		if err == nil {
			metrics.QueueDepth.Set(float64(count))
		}
	}
	refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func destinationDomain(rcpt string) string {
	_, domain, ok := directory.ParseAddress(rcpt)
	if !ok {
		return rcpt
	}
	return domain
}

// handle runs one delivery attempt for job and applies FR-3.4's retry/
// dead-letter policy to the outcome.
func (d *Deliverer) handle(ctx context.Context, job queue.Job) {
	// NFR-OBS-2: re-attach the correlation ID submission enqueued this job
	// with, so every log line below — and any webhook event this outcome
	// fires (see fire) — traces back to the same submission even though
	// this is a different role/process/replica than the one that accepted
	// it.
	ctx = logging.WithCorrelationID(ctx, job.CorrelationID)

	start := time.Now()
	err := d.attempt(ctx, job)
	metrics.DeliveryLatencySeconds.Observe(time.Since(start).Seconds())

	if err == nil {
		slog.InfoContext(ctx, "message delivered", "vhost", job.Vhost, "to", job.To,
			"attempt", job.Attempts+1, "duration", time.Since(start))
		_ = d.cfg.Queue.Complete(ctx, job.ID)
		d.fireDelivered(ctx, job)
		return
	}

	if isPermanent(err) {
		slog.WarnContext(ctx, "message bounced: permanent failure", "vhost", job.Vhost, "to", job.To,
			"attempt", job.Attempts+1, "error", err.Error())
		metrics.BouncesTotal.Inc()
		_ = d.cfg.Queue.Complete(ctx, job.ID)
		d.deliverBounce(ctx, job, err)
		d.fireBounced(ctx, job, err)
		return
	}

	if job.Attempts+1 >= d.cfg.MaxAttempts {
		exhausted := fmt.Errorf("exhausted %d delivery attempts, last error: %w", d.cfg.MaxAttempts, err)
		slog.WarnContext(ctx, "message bounced: attempts exhausted", "vhost", job.Vhost, "to", job.To,
			"attempts", job.Attempts+1, "error", err.Error())
		metrics.BouncesTotal.Inc()
		_ = d.cfg.Queue.Complete(ctx, job.ID)
		d.deliverBounce(ctx, job, exhausted)
		d.fireBounced(ctx, job, exhausted)
		return
	}

	next := time.Now().Add(d.nextBackoff(job.Attempts))
	slog.InfoContext(ctx, "message delivery deferred", "vhost", job.Vhost, "to", job.To,
		"attempt", job.Attempts+1, "error", err.Error(), "next_attempt_at", next)
	_ = d.cfg.Queue.Fail(ctx, job.ID, err, next)
	d.fireDeferred(ctx, job, err, next)
}

// attempt resolves job.To's MX hosts and tries delivery against them in
// preference order.
func (d *Deliverer) attempt(ctx context.Context, job queue.Job) error {
	domain := destinationDomain(job.To)
	if domain == job.To {
		return permanentErr(fmt.Errorf("deliverer: malformed recipient address %q", job.To))
	}

	mxs, err := d.lookupMX(ctx, domain)
	if err != nil {
		return err
	}

	rc, err := d.cfg.Store.Read(ctx, storage.MessageRef{Vhost: job.Vhost, Mailbox: storage.OutboxMailbox, Key: job.BodyRef})
	if err != nil {
		return temporaryErr(fmt.Errorf("deliverer: read staged body: %w", err))
	}
	body, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return temporaryErr(fmt.Errorf("deliverer: read staged body: %w", err))
	}

	return d.send(ctx, mxs, job, body)
}

func (d *Deliverer) nextBackoff(attempt int) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queue.FullJitter(attempt, d.cfg.BackoffBase, d.cfg.BackoffMax, d.rand)
}

func (d *Deliverer) fireDelivered(ctx context.Context, job queue.Job) {
	d.fire(ctx, job, webhook.EventMessageDelivered, map[string]any{
		"from": job.From, "to": job.To,
	})
}

func (d *Deliverer) fireBounced(ctx context.Context, job queue.Job, cause error) {
	d.fire(ctx, job, webhook.EventMessageBounced, map[string]any{
		"from": job.From, "to": job.To, "attempts": job.Attempts + 1, "error": cause.Error(),
	})
}

func (d *Deliverer) fireDeferred(ctx context.Context, job queue.Job, cause error, nextAttemptAt time.Time) {
	d.fire(ctx, job, webhook.EventMessageDeferred, map[string]any{
		"from": job.From, "to": job.To, "attempts": job.Attempts + 1,
		"error": cause.Error(), "nextAttemptAt": nextAttemptAt,
	})
}

func (d *Deliverer) fire(ctx context.Context, job queue.Job, eventType string, data any) {
	if d.cfg.Webhooks == nil {
		return
	}
	payload, err := webhook.NewEventPayload(uuid.NewString(), eventType, job.Vhost, data)
	if err != nil {
		return
	}
	_ = d.cfg.Webhooks.Enqueue(ctx, job.Vhost, eventType, payload)
}
