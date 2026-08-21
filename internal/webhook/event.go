package webhook

import (
	"encoding/json"
	"fmt"
	"time"
)

// Event type constants (FR-6.1's minimum set).
const (
	EventMessageReceived = "message.received"
	// EventMessageQueued fires once per accepted outbound send request —
	// from internal/api.MessageController.Send (the REST send endpoint)
	// and internal/platform/smtp/submission.go (authenticated SMTP
	// submission) — not once per recipient, distinct from the
	// per-recipient delivered/bounced/deferred events below, which report
	// internal/deliverer's later per-attempt outcomes.
	EventMessageQueued    = "message.queued"
	EventMessageDelivered = "message.delivered"
	EventMessageBounced   = "message.bounced"
	EventMessageDeferred  = "message.deferred"
	// EventMessageComplained is defined for FR-6.1 interface completeness
	// (Subscription.EventTypes can already filter on it), but nothing in
	// this codebase fires it yet: that requires ingesting ISP feedback-loop
	// (FBL) complaint reports, which isn't built — tracked as a gap for
	// Phase 6/GA, not silently promised as working.
	EventMessageComplained = "message.complained"
)

// envelope is the JSON body every webhook delivery carries, matching the
// Stripe/GitHub convention FR-6.2 already follows for the signature header.
type envelope struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Vhost     string          `json:"vhost"`
	CreatedAt time.Time       `json:"createdAt"`
	Data      json.RawMessage `json:"data"`
}

// NewEventPayload marshals data into the canonical event envelope Dispatch
// delivers, tagged with a fresh event ID shared across every subscription
// this event fans out to (so a receiver can dedupe retried/duplicate
// deliveries of the same logical event by ID).
func NewEventPayload(eventID, eventType, vhost string, data any) ([]byte, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("webhook: marshal event data: %w", err)
	}
	body, err := json.Marshal(envelope{
		ID: eventID, Type: eventType, Vhost: vhost, CreatedAt: time.Now().UTC(), Data: raw,
	})
	if err != nil {
		return nil, fmt.Errorf("webhook: marshal event envelope: %w", err)
	}
	return body, nil
}
