package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/mail"
	"time"

	"github.com/awesome-goose/goose/io/output"
	"github.com/awesome-goose/goose/types"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/apiauth"
	"github.com/isaiahiroko/envelope/internal/audit"
	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/logging"
	"github.com/isaiahiroko/envelope/internal/mailbuild"
	"github.com/isaiahiroko/envelope/internal/queue"
	"github.com/isaiahiroko/envelope/internal/storage"
	"github.com/isaiahiroko/envelope/internal/webhook"
)

// secondsPerDay mirrors internal/platform/smtp/submission.go's constant of
// the same name (see that file's doc for why quota enforcement here is
// duplicated rather than shared).
const secondsPerDay = 24 * 60 * 60

// MessageController is the REST alternative to authenticated SMTP
// submission (FR-3.x): POST an email as JSON instead of speaking SMTP.
// From here on it reuses exactly what submission already relies on — the
// same Store/Queue the deliverer drains regardless of which ingress path
// enqueued a job, the same per-vhost DKIM key and FR-3.7 daily quota, the
// same Outbox staging mailbox — so nothing downstream needs to know or
// care that a message arrived over HTTP instead of SMTP.
type MessageController struct {
	dir       *directory.Service `inject:""`
	tokens    apiauth.Store      `inject:""`
	admin     *AdminToken        `inject:""`
	rateLimit *RateLimitPolicy   `inject:""`
	audit     audit.Store        `inject:""`
	store     storage.Store      `inject:""`
	queue     queue.Backend      `inject:""`
	webhooks  webhook.Enqueuer   `inject:""`
	quota     *QuotaPolicy       `inject:""`
}

func (c *MessageController) Send(dto *SendMessageDto) types.Output {
	ctx := context.Background()

	// Authenticate/authorize first, before any resource lookup: a caller
	// with an invalid or wrong-account token learns nothing about whether
	// dto.From's vhost even exists.
	ac, errOut := requireAccountAccess(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.AccountID)
	if errOut != nil {
		return errOut
	}

	parsedFrom, err := mail.ParseAddress(dto.From)
	if err != nil {
		return output.BadRequest("from is not a valid email address")
	}
	_, domain, ok := directory.ParseAddress(parsedFrom.Address)
	if !ok {
		return output.BadRequest("from is not a valid email address")
	}

	v, ok := c.dir.Vhost(ctx, domain)
	if !ok {
		return output.NotFound("vhost not found for from address")
	}
	if !v.Active {
		return output.Forbidden("vhost is not active")
	}
	if !ac.IsAdmin && ac.AccountID != v.AccountID {
		return output.Forbidden("from address's vhost does not belong to this account")
	}
	if v.DKIMKey == nil {
		return output.ServiceUnavailable("no DKIM key configured for sending vhost")
	}

	recipients := uniqueRecipients(dto.To, dto.Cc, dto.Bcc)
	if len(recipients) == 0 {
		return output.BadRequest("at least one recipient (to, cc, or bcc) is required")
	}
	if dto.Text == "" && dto.HTML == "" {
		return output.BadRequest("text or html body is required")
	}

	attachments := make([]mailbuild.Attachment, len(dto.Attachments))
	for i, a := range dto.Attachments {
		content, err := base64.StdEncoding.DecodeString(a.ContentBase64)
		if err != nil {
			return output.BadRequest(fmt.Sprintf("attachment %q: contentBase64 is not valid base64", a.Filename))
		}
		attachments[i] = mailbuild.Attachment{Filename: a.Filename, ContentType: a.ContentType, Content: content}
	}

	for k := range dto.Headers {
		if mailbuild.IsReservedHeader(k) {
			return output.BadRequest(fmt.Sprintf("cannot override reserved header %q", k))
		}
	}

	if errOut := c.checkQuota(ctx, v); errOut != nil {
		return errOut
	}

	raw, err := mailbuild.Build(mailbuild.Message{
		From: dto.From, Domain: v.Domain,
		To: dto.To, Cc: dto.Cc, Bcc: dto.Bcc,
		Subject: dto.Subject, Text: dto.Text, HTML: dto.HTML,
		Attachments: attachments, Headers: dto.Headers,
	})
	if err != nil {
		return output.InternalServerError("failed to compose message")
	}

	signed, err := dkimSign(raw, v)
	if err != nil {
		return output.InternalServerError("DKIM signing failed")
	}

	correlationID := logging.NewCorrelationID()
	ctx = logging.WithCorrelationID(ctx, correlationID)

	jobIDs := make([]string, 0, len(recipients))
	for _, rcpt := range recipients {
		ref, err := c.store.Write(ctx, v.Domain, storage.OutboxMailbox, bytes.NewReader(signed))
		if err != nil {
			return output.InternalServerError("temporary storage failure")
		}

		job := queue.Job{
			ID:            uuid.NewString(),
			Vhost:         v.Domain,
			From:          parsedFrom.Address,
			To:            rcpt,
			BodyRef:       ref.Key,
			NextAttemptAt: time.Now(),
			CorrelationID: correlationID,
		}
		if err := c.queue.Enqueue(ctx, job); err != nil {
			return output.InternalServerError("queue unavailable")
		}
		jobIDs = append(jobIDs, job.ID)
	}

	c.fireQueued(ctx, v.Domain, parsedFrom.Address, recipients)

	recordAudit(ctx, c.audit, ac, "message.send", v.ID, dto.Subject)
	return output.Created(map[string]any{"queued": len(jobIDs), "vhostId": v.ID, "jobIds": jobIDs})
}

// checkQuota enforces FR-3.7 exactly the way
// internal/platform/smtp/submission.go's checkQuota does — duplicated, not
// shared, per this repo's existing convention of independently-declared
// copies of small interfaces/helpers across packages (see
// internal/api/ratelimit.go's apiLimiter doc).
func (c *MessageController) checkQuota(ctx context.Context, v directory.Vhost) types.Output {
	if c.quota == nil || c.quota.Limiter == nil || v.DailyQuota <= 0 {
		return nil
	}
	allowed, err := c.quota.Limiter.Allow(ctx, "quota:"+v.ID, float64(v.DailyQuota), float64(v.DailyQuota)/secondsPerDay)
	if err == nil && !allowed {
		return output.TooManyRequests("daily sending quota exceeded for this vhost, try again later")
	}
	return nil
}

// fireQueued fires message.queued once per accepted send request (not once
// per recipient) — a distinct "your send was accepted" signal from the
// deliverer's later per-recipient delivered/bounced/deferred events. A nil
// webhooks (unregistered, or a test that doesn't wire one) is a no-op, the
// same posture internal/platform/smtp.Config.Webhooks already takes.
func (c *MessageController) fireQueued(ctx context.Context, vhostDomain, from string, to []string) {
	if c.webhooks == nil {
		return
	}
	payload, err := webhook.NewEventPayload(uuid.NewString(), webhook.EventMessageQueued, vhostDomain, map[string]any{
		"from": from, "to": to,
	})
	if err != nil {
		return
	}
	_ = c.webhooks.Enqueue(ctx, vhostDomain, webhook.EventMessageQueued, payload)
}

// uniqueRecipients unions to/cc/bcc into one deduplicated recipient list,
// preserving first-seen order — a caller listing the same address in both
// to and cc gets one queued delivery to it, not two.
func uniqueRecipients(lists ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range lists {
		for _, addr := range list {
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out
}

// dkimSign is the identical inline call
// internal/platform/smtp/submission.go's Data handler makes — duplicated
// rather than shared, for the same reason checkQuota is (see that method's
// doc).
func dkimSign(body []byte, v directory.Vhost) ([]byte, error) {
	var signed bytes.Buffer
	if err := dkim.Sign(&signed, bytes.NewReader(body), &dkim.SignOptions{
		Domain:   v.Domain,
		Selector: v.DKIMSelector,
		Signer:   v.DKIMKey,
	}); err != nil {
		return nil, err
	}
	return signed.Bytes(), nil
}
