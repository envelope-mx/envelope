// Package api is the management API module: vhost and mailbox CRUD
// (TRD FR-1.1/FR-1.4/FR-5.1), boots on the stock Goose `api` platform.
package api

// Authorization is embedded (not literally — Goose's DTO binder doesn't
// flatten anonymous fields, see internal/api/auth.go's doc) as an
// identical field on every DTO below: FR-5.2 requires every request be
// authenticated, and the `header:"Authorization"` tag is how a controller
// method gets at the raw header value without a Context parameter (every
// handler here only ever receives its Dto).

type CreateVhostDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	AccountID     string `param:"accountId"`
	Domain        string `json:"domain"`
}

type ListVhostsDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	// Cursor/Limit implement FR-5.4's cursor-based pagination — see
	// directory.Service.ListVhosts's doc. Both optional: an empty Cursor
	// starts from the first page; Limit <= 0 uses
	// directory.DefaultVhostPageSize.
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

type GetVhostDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	ID            string `param:"id"`
}

type DeactivateVhostDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	ID            string `param:"id"`
}

// UpdateVhostPolicyDto is FR-1.2/NFR-COMP-1's vhost policy update — a full
// replace (see Service.UpdateVhostPolicy's doc), so callers should GetVhost
// first if they only mean to change one field.
type UpdateVhostPolicyDto struct {
	Authorization           string  `header:"Authorization"`
	ClientIP                string  `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	ID                      string  `param:"id"`
	MaxMessageBytes         int64   `json:"maxMessageBytes"`
	DailyQuota              int     `json:"dailyQuota"`
	SpamRejectThreshold     float64 `json:"spamRejectThreshold"`
	SpamQuarantineThreshold float64 `json:"spamQuarantineThreshold"`
	RetentionDays           int     `json:"retentionDays"`
}

type CreateMailboxDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	LocalPart     string `json:"localPart"`
	Password      string `json:"password"`
}

type ListMailboxesDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	// Cursor/Limit implement FR-5.4's cursor-based pagination — see
	// ListVhostsDto's doc for the pattern.
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

type GetMailboxDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	ID            string `param:"id"`
}

type DeleteMailboxDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	ID            string `param:"id"`
}

type CreateWebhookSubscriptionDto struct {
	Authorization string   `header:"Authorization"`
	ClientIP      string   `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string   `param:"vhostId"`
	URL           string   `json:"url"`
	Secret        string   `json:"secret"`
	EventTypes    []string `json:"eventTypes"`
}

type ListWebhookSubscriptionsDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	// Cursor/Limit implement FR-5.4's cursor-based pagination — see
	// ListVhostsDto's doc for the pattern.
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

type DisableWebhookSubscriptionDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	ID            string `param:"id"`
}

type ListWebhookAttemptsDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	ID            string `param:"id"`
	// Cursor/Limit implement FR-5.4's cursor-based pagination — see
	// ListVhostsDto's doc for the pattern.
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

// RedriveWebhookAttemptDto identifies the event to manually redrive
// (index/RUNBOOK.md §4.3) — ID is the subscription (matching every other
// webhook DTO's convention), EventID is the specific dead-lettered event.
type RedriveWebhookAttemptDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	ID            string `param:"id"`
	EventID       string `param:"eventId"`
}

type CreateTokenDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	AccountID     string `param:"accountId"`
	Label         string `json:"label"`
}

type ListTokensDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	AccountID     string `param:"accountId"`
	// Cursor/Limit implement FR-5.4's cursor-based pagination — see
	// ListVhostsDto's doc for the pattern.
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

type RevokeTokenDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	AccountID     string `param:"accountId"`
	ID            string `param:"id"`
}

type CreateAccountDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	Name          string `json:"name"`
}

type ListAccountsDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	// Cursor/Limit implement FR-5.4's cursor-based pagination — see
	// ListVhostsDto's doc for the pattern.
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

type GetAccountDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	ID            string `param:"id"`
}

type ListAccountAuditEntriesDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	AccountID     string `param:"accountId"`
	// Cursor/Limit implement FR-5.4's cursor-based pagination — see
	// ListVhostsDto's doc for the pattern.
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

// SendMessageDto is the REST alternative to authenticated SMTP submission
// (FR-3.x) — see MessageController.Send's doc for the full pipeline this
// feeds into. From identifies the sending mailbox's vhost (its domain must
// belong to AccountID); To/Cc/Bcc are the envelope recipients (Bcc is
// never serialized into the composed message's headers — see
// internal/mailbuild). Headers lets a caller set additional RFC5322
// headers, but not override ones Send writes itself (from, to, subject,
// date, message-id, mime-version, content-type,
// content-transfer-encoding) — Send rejects any collision with 400 rather
// than silently overriding or dropping it.
type SendMessageDto struct {
	Authorization string            `header:"Authorization"`
	ClientIP      string            `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	AccountID     string            `param:"accountId"`
	From          string            `json:"from"`
	To            []string          `json:"to"`
	Cc            []string          `json:"cc"`
	Bcc           []string          `json:"bcc"`
	Subject       string            `json:"subject"`
	Text          string            `json:"text"`
	HTML          string            `json:"html"`
	Attachments   []AttachmentDto   `json:"attachments"`
	Headers       map[string]string `json:"headers"`
}

// AttachmentDto is one file attached to a SendMessageDto — ContentBase64 is
// standard base64 (encoding/base64.StdEncoding), not the base64url
// variant.
type AttachmentDto struct {
	Filename      string `json:"filename"`
	ContentType   string `json:"contentType"`
	ContentBase64 string `json:"contentBase64"`
}

type ListAuditEntriesDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	VhostID       string `param:"vhostId"`
	// Cursor/Limit implement FR-5.4's cursor-based pagination — see
	// ListVhostsDto's doc for the pattern.
	Cursor string `query:"cursor"`
	Limit  int    `query:"limit"`
}

type ExportVhostDataDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	ID            string `param:"id"`
}

type DeleteVhostDataDto struct {
	Authorization string `header:"Authorization"`
	ClientIP      string `header:"X-Forwarded-For"` // NFR-SEC-4, see RateLimitPolicy's doc
	ID            string `param:"id"`
}
