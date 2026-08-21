// Package logging implements NFR-OBS-2: structured (JSON) logs with a
// correlation ID spanning inbound acceptance -> filter verdict -> storage
// write -> webhook dispatch, so one message's lifecycle is traceable across
// roles/replicas, not just within one process.
//
// The correlation ID is carried on context.Context for the synchronous part
// of a request (e.g. inboundSession.Data's filter-evaluate-store-enqueue
// sequence), and persisted onto the durable rows that cross into a later,
// possibly different-process/different-replica async step
// (queue.Job.CorrelationID, webhook.DeliveryJob.CorrelationID) so
// internal/deliverer and internal/webhook.Dispatcher can re-attach the same
// ID to their own logs when they eventually process that row — the "across
// roles/replicas" part NFR-OBS-2 asks for, which a context value alone
// cannot satisfy once work crosses a process boundary via a database row.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/google/uuid"
)

type correlationIDKey struct{}

// NewCorrelationID returns a fresh ID for a new unit of work (one SMTP
// transaction, one outbound job) to be attached via WithCorrelationID.
func NewCorrelationID() string {
	return uuid.NewString()
}

// WithCorrelationID returns a context carrying id, picked up automatically
// by any log call made with that context through a logger built by
// NewJSONLogger (via contextHandler below) — callers never need to attach
// the attribute manually at each log call site.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, correlationIDKey{}, id)
}

// CorrelationID returns the ID attached to ctx, or "" if none.
func CorrelationID(ctx context.Context) string {
	id, _ := ctx.Value(correlationIDKey{}).(string)
	return id
}

// contextHandler wraps an slog.Handler, injecting a correlation_id
// attribute pulled from the record's context whenever one is present. This
// is what makes slog.InfoContext(ctx, ...) calls throughout the codebase
// automatically carry the ID attached via WithCorrelationID, without every
// call site having to remember to pass it as an explicit attribute.
type contextHandler struct {
	slog.Handler
}

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := CorrelationID(ctx); id != "" {
		r.AddAttrs(slog.String("correlation_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}

// NewJSONLogger returns a *slog.Logger writing JSON records to w at the
// given level, automatically attaching a correlation_id attribute (see
// WithCorrelationID) whenever the logging call's context carries one.
func NewJSONLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(contextHandler{slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})})
}

// LevelFromEnv parses a level name ("debug", "info", "warn"/"warning",
// "error") case-insensitively, defaulting to Info for an empty or
// unrecognized value rather than failing boot over a log-verbosity typo.
func LevelFromEnv(v string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
