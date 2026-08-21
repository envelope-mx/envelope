package api

import (
	"context"
	"errors"

	"github.com/awesome-goose/goose/io/output"
	"github.com/awesome-goose/goose/types"
	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/apiauth"
	"github.com/isaiahiroko/envelope/internal/audit"
	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/webhook"
)

// WebhookController is the webhook subscription management (FR-6.5) and
// dead-letter delivery-history (FR-6.4) API. It depends on webhook.Store
// directly, the same way VhostController depends on *directory.Service —
// this is CRUD/history surface, not the minimal contract
// internal/webhook.Dispatcher needs to enqueue and deliver events.
type WebhookController struct {
	dir       *directory.Service `inject:""`
	store     webhook.Store      `inject:""`
	redrive   *RedrivePolicy     `inject:""`
	tokens    apiauth.Store      `inject:""`
	admin     *AdminToken        `inject:""`
	rateLimit *RateLimitPolicy   `inject:""`
	audit     audit.Store        `inject:""`
}

// RedrivePolicy wraps webhook.Redriver the same way RateLimitPolicy wraps
// its own limiter and AdminToken wraps its bootstrap value — a
// pointer-to-struct wrapping an optional interface field, not a bare
// interface, so an unregistered *RedrivePolicy zero-values safely instead
// of hard-erroring at container creation (Goose's DI container hard-errors
// on an unregistered bare interface field, but silently zero-values an
// unregistered pointer-to-struct — see core/container.go). A nil
// Dispatcher means RedriveAttempt returns 503, not a boot-time dependency
// every deployment or test has to wire.
type RedrivePolicy struct {
	Dispatcher webhook.Redriver
}

// vhostDomain resolves the :vhostId URL param to that vhost's domain.
// webhook.Subscription.Vhost is keyed by domain, not vhost ID, matching
// every event-firing call site's own "vhost" convention
// (directory.Directory's Vhost/VhostActive/Authenticate, queue.Job.Vhost,
// inboundSession.fireReceived, deliverer.fire — all of them pass the
// domain string, never the vhost's UUID, because a queued job or an
// inbound connection has the domain on hand but never looks up the
// vhost's ID). The REST routes still nest under /vhosts/:vhostId/webhooks
// for URL consistency with CreateMailbox's pattern; this is the one place
// that translates between the two.
func (c *WebhookController) vhostDomain(ctx context.Context, vhostID string) (string, types.Output) {
	v, err := c.dir.GetVhost(ctx, vhostID)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return "", output.NotFound("vhost not found")
		}
		return "", output.InternalServerError("failed to verify vhost")
	}
	return v.Domain, nil
}

// CreateSubscription registers a new webhook endpoint for a vhost
// (FR-6.5). The caller supplies its own signing secret (used to verify
// FR-6.2's X-Envelope-Signature header) — it's accepted here but never
// echoed back in any response (see webhookSubscriptionView).
func (c *WebhookController) CreateSubscription(dto *CreateWebhookSubscriptionDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID)
	if errOut != nil {
		return errOut
	}
	if dto.URL == "" || dto.Secret == "" {
		return output.BadRequest("url and secret are required")
	}

	domain, errOut := c.vhostDomain(ctx, dto.VhostID)
	if errOut != nil {
		return errOut
	}

	sub := webhook.Subscription{
		ID: uuid.NewString(), Vhost: domain, URL: dto.URL, Secret: dto.Secret, EventTypes: dto.EventTypes,
	}
	if err := c.store.CreateSubscription(ctx, sub); err != nil {
		return output.InternalServerError("failed to create webhook subscription")
	}
	recordAudit(ctx, c.audit, ac, "webhook.create", dto.VhostID, dto.URL)
	return output.Created(newWebhookSubscriptionView(dto.VhostID, sub))
}

// ListSubscriptions is cursor-paginated (FR-5.4) via dto.Cursor/dto.Limit —
// see directory.Service.ListVhosts's doc for the pattern and
// webhook.Store.ListSubscriptions's doc for why the underlying Store method
// this calls (ListSubscriptionsPage) is a sibling of, not a replacement
// for, the unbounded ListSubscriptions internal callers still use.
func (c *WebhookController) ListSubscriptions(dto *ListWebhookSubscriptionsDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID); errOut != nil {
		return errOut
	}

	domain, errOut := c.vhostDomain(ctx, dto.VhostID)
	if errOut != nil {
		return errOut
	}

	subs, err := c.store.ListSubscriptionsPage(ctx, domain, dto.Cursor, dto.Limit)
	if err != nil {
		return output.InternalServerError("failed to list webhook subscriptions")
	}
	views := make([]webhookSubscriptionView, len(subs))
	for i, s := range subs {
		views[i] = newWebhookSubscriptionView(dto.VhostID, s)
	}

	nextCursor := ""
	limit := dto.Limit
	if limit <= 0 || limit > webhook.MaxPageSize {
		limit = webhook.DefaultPageSize
	}
	if len(subs) == limit {
		nextCursor = subs[len(subs)-1].ID
	}
	return output.SuccessWithMeta("", views, map[string]any{"nextCursor": nextCursor})
}

// DisableSubscription soft-disables a subscription, preserving its
// delivery history (FR-6.5).
func (c *WebhookController) DisableSubscription(dto *DisableWebhookSubscriptionDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID)
	if errOut != nil {
		return errOut
	}

	domain, errOut := c.vhostDomain(ctx, dto.VhostID)
	if errOut != nil {
		return errOut
	}

	if err := c.store.DisableSubscription(ctx, domain, dto.ID); err != nil {
		if errors.Is(err, webhook.ErrNotFound) {
			return output.NotFound("webhook subscription not found")
		}
		return output.InternalServerError("failed to disable webhook subscription")
	}
	recordAudit(ctx, c.audit, ac, "webhook.disable", dto.VhostID, dto.ID)
	return output.Success("webhook subscription disabled", nil)
}

// ListAttempts returns a page of a subscription's delivery attempt
// history, cursor-paginated (FR-5.4) via dto.Cursor/dto.Limit — FR-6.4's
// dead-letter visibility: an event that exhausted its retries is no longer
// in the active queue, but every attempt made against it stays visible
// here.
func (c *WebhookController) ListAttempts(dto *ListWebhookAttemptsDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID); errOut != nil {
		return errOut
	}

	domain, errOut := c.vhostDomain(ctx, dto.VhostID)
	if errOut != nil {
		return errOut
	}

	attempts, err := c.store.ListAttemptsPage(ctx, domain, dto.ID, dto.Cursor, dto.Limit)
	if err != nil {
		return output.InternalServerError("failed to list delivery attempts")
	}
	views := make([]webhookAttemptView, len(attempts))
	for i, a := range attempts {
		views[i] = newWebhookAttemptView(a)
	}

	nextCursor := ""
	limit := dto.Limit
	if limit <= 0 || limit > webhook.MaxPageSize {
		limit = webhook.DefaultPageSize
	}
	if len(attempts) == limit {
		nextCursor = attempts[len(attempts)-1].ID
	}
	return output.SuccessWithMeta("", views, map[string]any{"nextCursor": nextCursor})
}

// RedriveAttempt manually retries a dead-lettered event (docs/RUNBOOK.md
// §4.3, closing the "no retry now endpoint" gap) — see
// webhook.Dispatcher.Redrive's doc for exactly what it does. Returns 503 if
// this deployment has no Dispatcher wired (c.redrive.Dispatcher is nil —
// see RedrivePolicy's doc).
func (c *WebhookController) RedriveAttempt(dto *RedriveWebhookAttemptDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID)
	if errOut != nil {
		return errOut
	}
	if c.redrive == nil || c.redrive.Dispatcher == nil {
		return output.ServiceUnavailable("manual redrive is not configured on this deployment")
	}

	domain, errOut := c.vhostDomain(ctx, dto.VhostID)
	if errOut != nil {
		return errOut
	}

	if err := c.redrive.Dispatcher.Redrive(ctx, domain, dto.ID, dto.EventID); err != nil {
		if errors.Is(err, webhook.ErrNotFound) {
			return output.NotFound("subscription or event not found")
		}
		return output.InternalServerError("failed to redrive webhook delivery")
	}
	recordAudit(ctx, c.audit, ac, "webhook.redrive", dto.VhostID, dto.EventID)
	return output.Success("webhook delivery redriven", nil)
}
