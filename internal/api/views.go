package api

import (
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/envelope-mx/envelope/internal/apiauth"
	"github.com/envelope-mx/envelope/internal/audit"
	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/webhook"
)

// vhostView is what the API returns for a vhost — deliberately excludes
// directory.Vhost.DKIMKey (the private key): only its derived DNS record
// text is ever serialized, never the key material itself.
type vhostView struct {
	ID                      string  `json:"id"`
	AccountID               string  `json:"accountId"`
	Domain                  string  `json:"domain"`
	Active                  bool    `json:"active"`
	MaxMessageBytes         int64   `json:"maxMessageBytes"`
	DailyQuota              int     `json:"dailyQuota"`
	SpamRejectThreshold     float64 `json:"spamRejectThreshold"`
	SpamQuarantineThreshold float64 `json:"spamQuarantineThreshold"`
	// RetentionDays is NFR-COMP-1's per-vhost retention window; 0 means
	// unconfigured (internal/retention.Purger's platform default applies).
	RetentionDays int    `json:"retentionDays"`
	DKIMSelector  string `json:"dkimSelector,omitempty"`
	// DKIMDNSRecord is the TXT record value to publish at
	// "<selector>._domainkey.<domain>" (FR-5.1: "fetch DKIM public key +
	// DNS record text for a vhost"). Empty when the key wasn't loaded
	// (ListVhosts doesn't hydrate it; GetVhost does).
	DKIMDNSRecord string `json:"dkimDnsRecord,omitempty"`
}

func newVhostView(v directory.Vhost) vhostView {
	view := vhostView{
		ID: v.ID, AccountID: v.AccountID, Domain: v.Domain, Active: v.Active,
		MaxMessageBytes:         v.MaxMessageBytes,
		DailyQuota:              v.DailyQuota,
		SpamRejectThreshold:     v.SpamRejectThreshold,
		SpamQuarantineThreshold: v.SpamQuarantineThreshold,
		RetentionDays:           v.RetentionDays,
		DKIMSelector:            v.DKIMSelector,
	}
	if v.DKIMKey != nil {
		der, err := x509.MarshalPKIXPublicKey(&v.DKIMKey.PublicKey)
		if err == nil {
			view.DKIMDNSRecord = "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
		}
	}
	return view
}

// mailboxView is what the API returns for a mailbox — excludes
// directory.Mailbox.PasswordHash.
type mailboxView struct {
	ID        string `json:"id"`
	VhostID   string `json:"vhostId"`
	LocalPart string `json:"localPart"`
}

func newMailboxView(m directory.Mailbox) mailboxView {
	return mailboxView{ID: m.ID, VhostID: m.VhostID, LocalPart: m.LocalPart}
}

// webhookSubscriptionView is what the API returns for a subscription —
// excludes webhook.Subscription.Secret: the caller already knows it (they
// supplied it at creation), and it's never echoed back afterward.
type webhookSubscriptionView struct {
	ID         string   `json:"id"`
	VhostID    string   `json:"vhostId"`
	URL        string   `json:"url"`
	EventTypes []string `json:"eventTypes,omitempty"`
	Disabled   bool     `json:"disabled"`
}

// newWebhookSubscriptionView takes vhostID explicitly rather than reading
// s.Vhost: internally a Subscription is keyed by domain (see
// WebhookController.vhostDomain's doc), but the API's public shape mirrors
// every other resource's vhostId (the UUID from the URL), not the domain.
func newWebhookSubscriptionView(vhostID string, s webhook.Subscription) webhookSubscriptionView {
	return webhookSubscriptionView{
		ID: s.ID, VhostID: vhostID, URL: s.URL, EventTypes: s.EventTypes, Disabled: s.Disabled,
	}
}

// webhookAttemptView is what the API returns for a delivery attempt
// (FR-6.4's dead-letter visibility).
type webhookAttemptView struct {
	ID          string    `json:"id"`
	EventID     string    `json:"eventId"`
	Attempt     int       `json:"attempt"`
	StatusCode  int       `json:"statusCode"`
	Error       string    `json:"error,omitempty"`
	AttemptedAt time.Time `json:"attemptedAt"`
}

func newWebhookAttemptView(a webhook.DeliveryAttempt) webhookAttemptView {
	return webhookAttemptView{
		ID: a.ID, EventID: a.EventID, Attempt: a.Attempt, StatusCode: a.StatusCode,
		Error: a.Error, AttemptedAt: a.AttemptedAt,
	}
}

// tokenView is what the API returns for a token. Token is only ever
// non-empty immediately after CreateToken — every other response (list)
// passes "" (omitted from the JSON entirely), since the raw value is
// never retrievable again after the moment it's minted.
type tokenView struct {
	ID        string    `json:"id"`
	AccountID string    `json:"accountId"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	Token     string    `json:"token,omitempty"`
}

// accountView is what the API returns for an account.
type accountView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

func newAccountView(a directory.Account) accountView {
	return accountView{ID: a.ID, Name: a.Name, CreatedAt: a.CreatedAt}
}

// accountWithTokenView is AccountController.CreateAccount's response —
// the account plus its auto-issued first token, following the same
// "raw token value visible exactly once" convention newTokenView already
// establishes.
type accountWithTokenView struct {
	Account accountView `json:"account"`
	Token   tokenView   `json:"token"`
}

func newAccountWithTokenView(a directory.Account, t apiauth.Token, raw string) accountWithTokenView {
	return accountWithTokenView{Account: newAccountView(a), Token: newTokenView(t, raw)}
}

// auditEntryView is what the API returns for an audit log entry
// (NFR-COMP-4).
type auditEntryView struct {
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

func newAuditEntryView(e audit.Entry) auditEntryView {
	return auditEntryView{Actor: e.Actor, Action: e.Action, Detail: e.Detail, At: e.At}
}

func newTokenView(t apiauth.Token, rawToken string) tokenView {
	return tokenView{
		ID: t.ID, AccountID: t.AccountID, Label: t.Label, CreatedAt: t.CreatedAt, Token: rawToken,
	}
}

// messageExportView is one stored message as returned by NFR-COMP-2's data
// export — unlike every other view in this file, it includes the full
// message body (base64-encoded), since an export that omitted the actual
// data wouldn't be one.
type messageExportView struct {
	Mailbox   string    `json:"mailbox"`
	Size      int64     `json:"size"`
	Flags     []string  `json:"flags,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	Body      string    `json:"body"`
}

// dataExportView is NFR-COMP-2's full per-vhost export: policy, mailboxes,
// messages, webhook subscriptions, and audit history — everything else in
// this file's views already excludes secrets (DKIM private key, password
// hashes, webhook secrets, raw tokens), so composing them here doesn't
// leak anything the individual list endpoints wouldn't already avoid.
type dataExportView struct {
	Vhost                vhostView                 `json:"vhost"`
	Mailboxes            []mailboxView             `json:"mailboxes"`
	Messages             []messageExportView       `json:"messages"`
	WebhookSubscriptions []webhookSubscriptionView `json:"webhookSubscriptions"`
	AuditLog             []auditEntryView          `json:"auditLog"`
}

func newDataExportView(
	v directory.Vhost, mailboxes []directory.Mailbox, messages []messageExportView,
	vhostID string, subs []webhook.Subscription, entries []audit.Entry,
) dataExportView {
	mbViews := make([]mailboxView, len(mailboxes))
	for i, m := range mailboxes {
		mbViews[i] = newMailboxView(m)
	}
	subViews := make([]webhookSubscriptionView, len(subs))
	for i, s := range subs {
		subViews[i] = newWebhookSubscriptionView(vhostID, s)
	}
	entryViews := make([]auditEntryView, len(entries))
	for i, e := range entries {
		entryViews[i] = newAuditEntryView(e)
	}
	return dataExportView{
		Vhost: newVhostView(v), Mailboxes: mbViews, Messages: messages,
		WebhookSubscriptions: subViews, AuditLog: entryViews,
	}
}
