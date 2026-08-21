package queue

import "time"

// Job is a unit of outbound delivery work (TRD §7 outbound_jobs).
type Job struct {
	ID            string
	Vhost         string
	From          string
	To            string
	BodyRef       string // points at the message body in storage.Store
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
	// CorrelationID carries NFR-OBS-2's log correlation ID across the
	// submission -> deliverer process/role boundary, set by
	// internal/platform/smtp's submission session at enqueue time (from
	// the ctx its own logs already use) and re-attached by
	// internal/deliverer.Deliverer.handle so a bounce/deferral/delivery
	// logged by a completely different replica still carries the same ID
	// as the original submission.
	CorrelationID string
}
