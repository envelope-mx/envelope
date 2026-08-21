package smtp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	gosasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/google/uuid"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/logging"
	"github.com/envelope-mx/envelope/internal/queue"
	"github.com/envelope-mx/envelope/internal/webhook"
)

// submissionBackend implements go-smtp's Backend for the submission role
// (FR-3.x): authenticated outbound relay.
type submissionBackend struct {
	cfg Config
}

func (b *submissionBackend) NewSession(_ *gosmtp.Conn) (gosmtp.Session, error) {
	return &submissionSession{cfg: b.cfg}, nil
}

type submissionSession struct {
	cfg Config

	authLocal string
	authVhost string

	from          string
	rcpts         []string
	correlationID string // NFR-OBS-2, fresh per transaction (see Mail)
}

var (
	_ gosmtp.Session     = (*submissionSession)(nil)
	_ gosmtp.AuthSession = (*submissionSession)(nil)
)

func (s *submissionSession) AuthMechanisms() []string {
	return []string{gosasl.Plain}
}

// Auth returns a SASL PLAIN server that checks the given username/password
// against the Directory (FR-3.1). The username must be a full email
// address ("local@vhost") so the authenticated identity's sending vhost is
// known for DKIM signing (FR-3.2).
func (s *submissionSession) Auth(mech string) (gosasl.Server, error) {
	if mech != gosasl.Plain {
		return nil, errors.New("smtp: unsupported auth mechanism")
	}
	return gosasl.NewPlainServer(func(_, username, password string) error {
		local, vhost, ok := directory.ParseAddress(username)
		if !ok {
			return errors.New("smtp: username must be an email address")
		}
		if !s.cfg.Directory.Authenticate(context.Background(), vhost, local, password) {
			return gosmtp.ErrAuthFailed
		}
		s.authLocal = local
		s.authVhost = vhost
		return nil
	}), nil
}

func (s *submissionSession) Reset() {
	s.from = ""
	s.rcpts = nil
	s.correlationID = ""
}

func (s *submissionSession) Logout() error { return nil }

// Mail refuses unauthenticated submission (FR-3.1).
func (s *submissionSession) Mail(from string, _ *gosmtp.MailOptions) error {
	if s.authLocal == "" {
		return &gosmtp.SMTPError{
			Code:         530,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 0},
			Message:      "authentication required",
		}
	}
	s.correlationID = logging.NewCorrelationID() // NFR-OBS-2, see inboundSession.Mail's doc
	s.from = from
	return nil
}

func (s *submissionSession) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	s.rcpts = append(s.rcpts, to)
	return nil
}

// Data DKIM-signs the message using the authenticated vhost's key
// (FR-3.2), stages the signed body in storage, and enqueues one durable
// job per recipient (FR-3.3) before returning success.
func (s *submissionSession) Data(r io.Reader) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	ctx := logging.WithCorrelationID(context.Background(), s.correlationID)

	vhost, ok := s.cfg.Directory.Vhost(ctx, s.authVhost)
	if !ok || vhost.DKIMKey == nil {
		return &gosmtp.SMTPError{Code: 451, Message: "no DKIM key configured for sending vhost"}
	}

	if err := s.checkQuota(ctx, vhost); err != nil {
		return err
	}

	var signed bytes.Buffer
	if err := dkim.Sign(&signed, bytes.NewReader(body), &dkim.SignOptions{
		Domain:   vhost.Domain,
		Selector: vhost.DKIMSelector,
		Signer:   vhost.DKIMKey,
	}); err != nil {
		return &gosmtp.SMTPError{Code: 451, Message: "DKIM signing failed"}
	}

	for _, rcpt := range s.rcpts {
		ref, err := s.cfg.Store.Write(ctx, s.authVhost, OutboxMailbox, bytes.NewReader(signed.Bytes()))
		if err != nil {
			return &gosmtp.SMTPError{Code: 451, Message: "temporary storage failure"}
		}

		job := queue.Job{
			ID:            uuid.NewString(),
			Vhost:         s.authVhost,
			From:          s.from,
			To:            rcpt,
			BodyRef:       ref.Key,
			NextAttemptAt: time.Now(),
			CorrelationID: s.correlationID, // NFR-OBS-2: re-attached by internal/deliverer.handle
		}
		if err := s.cfg.Queue.Enqueue(ctx, job); err != nil {
			return &gosmtp.SMTPError{Code: 451, Message: "queue unavailable"}
		}
		slog.InfoContext(ctx, "outbound message queued", "vhost", s.authVhost, "to", rcpt, "job_id", job.ID)
	}
	s.fireQueued(ctx)
	return nil
}

// fireQueued fires message.queued once per accepted submission (not once
// per recipient — see webhook.EventMessageQueued's doc), mirroring
// inboundSession.fireReceived's shape. A nil Webhooks (unregistered, or a
// test that doesn't wire one) is a no-op.
func (s *submissionSession) fireQueued(ctx context.Context) {
	if s.cfg.Webhooks == nil {
		return
	}
	payload, err := webhook.NewEventPayload(uuid.NewString(), webhook.EventMessageQueued, s.authVhost, map[string]any{
		"from": s.from, "to": s.rcpts,
	})
	if err != nil {
		return
	}
	_ = s.cfg.Webhooks.Enqueue(ctx, s.authVhost, webhook.EventMessageQueued, payload)
}

// secondsPerDay spreads a vhost's DailyQuota's refill evenly across 24h
// when checkQuota treats it as a token-bucket capacity — see Config.Quota's
// doc for why a rolling window stands in for a literal calendar-day reset.
const secondsPerDay = 24 * 60 * 60

// checkQuota enforces FR-3.7: a vhost with DailyQuota configured that has
// exhausted its bucket gets a clear, temporary rejection (the quota
// refills continuously, so retrying later is meaningful) rather than
// having its message silently dropped later in the queue.
func (s *submissionSession) checkQuota(ctx context.Context, vhost directory.Vhost) error {
	if s.cfg.Quota == nil || vhost.DailyQuota <= 0 {
		return nil
	}

	allowed, err := s.cfg.Quota.Allow(ctx, "quota:"+vhost.ID, float64(vhost.DailyQuota), float64(vhost.DailyQuota)/secondsPerDay)
	if err != nil || allowed {
		return nil
	}
	return &gosmtp.SMTPError{
		Code:         452,
		EnhancedCode: gosmtp.EnhancedCode{4, 7, 1},
		Message:      "daily sending quota exceeded for this vhost, try again later",
	}
}
