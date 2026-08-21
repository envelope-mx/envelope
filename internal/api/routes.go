package api

import "github.com/awesome-goose/goose/modules/router"

var ROUTES = router.ForRoutes(
	// Accounts — platform-level create (admin-only, auto-issues the
	// account's first token), self-or-admin read.
	router.Post("accounts", []any{&AccountController{}, "CreateAccount"}),
	router.Get("accounts", []any{&AccountController{}, "ListAccounts"}),
	router.Get("accounts/:id", []any{&AccountController{}, "GetAccount"}),
	router.Get("accounts/:accountId/audit-log", []any{&AccountController{}, "ListEntries"}),

	// Vhosts — creation is self-serve under an account (or admin, for any
	// account); everything else stays nested under /vhosts/:vhostId, its
	// authorization now resolving through the vhost's owning account.
	router.Post("accounts/:accountId/vhosts", []any{&VhostController{}, "CreateVhost"}),
	router.Get("vhosts", []any{&VhostController{}, "ListVhosts"}),
	router.Get("vhosts/:id", []any{&VhostController{}, "GetVhost"}),
	router.Patch("vhosts/:id/deactivate", []any{&VhostController{}, "DeactivateVhost"}),
	router.Patch("vhosts/:id/policy", []any{&VhostController{}, "UpdateVhostPolicy"}),

	router.Post("vhosts/:vhostId/mailboxes", []any{&VhostController{}, "CreateMailbox"}),
	router.Get("vhosts/:vhostId/mailboxes", []any{&VhostController{}, "ListMailboxes"}),
	router.Get("vhosts/:vhostId/mailboxes/:id", []any{&VhostController{}, "GetMailbox"}),
	router.Delete("vhosts/:vhostId/mailboxes/:id", []any{&VhostController{}, "DeleteMailbox"}),

	router.Post("vhosts/:vhostId/webhooks", []any{&WebhookController{}, "CreateSubscription"}),
	router.Get("vhosts/:vhostId/webhooks", []any{&WebhookController{}, "ListSubscriptions"}),
	router.Patch("vhosts/:vhostId/webhooks/:id/disable", []any{&WebhookController{}, "DisableSubscription"}),
	router.Get("vhosts/:vhostId/webhooks/:id/attempts", []any{&WebhookController{}, "ListAttempts"}),
	router.Post("vhosts/:vhostId/webhooks/:id/attempts/:eventId/redrive", []any{&WebhookController{}, "RedriveAttempt"}),

	// Tokens — account-scoped, not vhost-scoped.
	router.Post("accounts/:accountId/tokens", []any{&TokenController{}, "CreateToken"}),
	router.Get("accounts/:accountId/tokens", []any{&TokenController{}, "ListTokens"}),
	router.Delete("accounts/:accountId/tokens/:id", []any{&TokenController{}, "RevokeToken"}),

	router.Get("vhosts/:vhostId/audit-log", []any{&AuditController{}, "ListEntries"}),

	router.Get("vhosts/:id/export", []any{&DataController{}, "Export"}),
	router.Delete("vhosts/:id/data", []any{&DataController{}, "Delete"}),

	// Send email via REST, an alternative to authenticated SMTP submission.
	router.Post("accounts/:accountId/messages", []any{&MessageController{}, "Send"}),
)
