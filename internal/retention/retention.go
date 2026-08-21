// Package retention implements NFR-COMP-1: per-vhost-configurable message
// retention, purged from both metadata and body storage within the
// retention window. Runs as a headless background sweep (the same
// context-driven-loop shape internal/deliverer.Deliverer.Run and
// internal/webhook.Dispatcher.Run already use), not a one-shot CLI job —
// TRD §2.1's "cron module" was the originally-imagined mechanism, but that
// module's fields are only populated through Goose's DI container during
// module traversal, the same constraint that ruled it out for rate
// limiting and quotas (internal/ratelimit's package doc); a plain ticker
// loop sidesteps it the same way.
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/logging"
	"github.com/envelope-mx/envelope/internal/metrics"
	"github.com/envelope-mx/envelope/internal/storage"
)

// DefaultRetentionDays applies to any vhost with RetentionDays <= 0 (the
// existing FR-1.2 "0 means unconfigured" convention). A starting point,
// not a legally reviewed number — deployments with real compliance
// requirements should set directory.VhostPolicy.RetentionDays explicitly
// per vhost via PATCH /vhosts/:id/policy rather than relying on this.
const DefaultRetentionDays = 90

// DefaultSweepInterval bounds how often Run re-scans every vhost. Purging
// is not time-critical the way mail delivery is, so a long interval is the
// right default — a sweep that ran every second would mean nothing at
// realistic retention windows measured in weeks/months, just wasted work.
const DefaultSweepInterval = 24 * time.Hour

// vhostLister is the narrow slice of *directory.Service this package
// depends on — an interface (not the concrete type) purely so tests can
// supply an in-memory fake instead of standing up Postgres, the same
// reason internal/platform/smtp.RateLimiter is an interface instead of
// importing internal/ratelimit's concrete type directly.
type vhostLister interface {
	ListVhosts(ctx context.Context, cursor string, limit int) ([]directory.Vhost, error)
}

// Purger sweeps every vhost on an interval, deleting any message older
// than that vhost's configured (or the platform default) retention
// window.
type Purger struct {
	Directory vhostLister
	Store     storage.Store

	// DefaultRetentionDays overrides the package-level DefaultRetentionDays
	// when > 0 (an operator-wide default distinct from any one vhost's
	// override).
	DefaultRetentionDays int
	// SweepInterval overrides DefaultSweepInterval when > 0.
	SweepInterval time.Duration

	// Now is overridden in tests to avoid depending on wall-clock time.
	Now func() time.Time
}

func (p *Purger) defaultDays() int {
	if p.DefaultRetentionDays > 0 {
		return p.DefaultRetentionDays
	}
	return DefaultRetentionDays
}

func (p *Purger) sweepInterval() time.Duration {
	if p.SweepInterval > 0 {
		return p.SweepInterval
	}
	return DefaultSweepInterval
}

func (p *Purger) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Run sweeps immediately, then on SweepInterval, until ctx is cancelled —
// the same "run once at boot, then on a ticker" shape
// internal/deliverer.Deliverer.sampleQueueDepth uses for the same reason:
// a freshly booted process shouldn't wait a full interval before its first
// useful work.
func (p *Purger) Run(ctx context.Context) error {
	ticker := time.NewTicker(p.sweepInterval())
	defer ticker.Stop()

	p.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			p.Sweep(ctx)
		}
	}
}

// Sweep runs one full pass over every vhost. Exported so callers (the
// "run the retention sweep now" operational task in index/RUNBOOK.md, and
// tests) don't have to wait out a real interval to trigger one.
func (p *Purger) Sweep(ctx context.Context) {
	// One correlation ID per sweep (NFR-OBS-2), not per deleted message —
	// this is a batch operation, and grouping every purge log line from
	// one pass under a single ID is more useful for tracing "what did this
	// sweep do" than giving each individual deletion its own unrelated ID.
	ctx = logging.WithCorrelationID(ctx, logging.NewCorrelationID())

	cursor := ""
	for {
		if ctx.Err() != nil {
			return
		}
		vhosts, err := p.Directory.ListVhosts(ctx, cursor, directory.DefaultVhostPageSize)
		if err != nil {
			slog.WarnContext(ctx, "retention: list vhosts failed", "error", err)
			return
		}
		for _, v := range vhosts {
			p.purgeVhost(ctx, v)
		}
		if len(vhosts) < directory.DefaultVhostPageSize {
			return
		}
		cursor = vhosts[len(vhosts)-1].ID
	}
}

func (p *Purger) purgeVhost(ctx context.Context, v directory.Vhost) {
	days := v.RetentionDays
	if days <= 0 {
		days = p.defaultDays()
	}
	cutoff := p.now().AddDate(0, 0, -days)

	messages, err := p.Store.ListVhost(ctx, v.Domain)
	if err != nil {
		slog.WarnContext(ctx, "retention: list messages failed", "vhost", v.Domain, "error", err)
		return
	}

	for _, m := range messages {
		// A zero CreatedAt means the backend couldn't determine an age
		// (shouldn't happen for either shipped backend, see storage.Store's
		// doc) — skip rather than guess, since purging is destructive and
		// irreversible.
		if m.CreatedAt.IsZero() || m.CreatedAt.After(cutoff) {
			continue
		}
		if err := p.Store.Delete(ctx, m.Ref); err != nil {
			slog.WarnContext(ctx, "retention: delete failed",
				"vhost", v.Domain, "mailbox", m.Ref.Mailbox, "key", m.Ref.Key, "error", err)
			continue
		}
		metrics.RetentionPurgedTotal.Inc()
		slog.InfoContext(ctx, "retention: message purged",
			"vhost", v.Domain, "mailbox", m.Ref.Mailbox, "created_at", m.CreatedAt, "retention_days", days)
	}
}
