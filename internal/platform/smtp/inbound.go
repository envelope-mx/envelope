package smtp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/filter"
	"github.com/isaiahiroko/envelope/internal/logging"
	"github.com/isaiahiroko/envelope/internal/metrics"
	"github.com/isaiahiroko/envelope/internal/webhook"
)

// defaultMaxMessageBytes is the server-wide fallback ceiling when neither
// Config.MaxMessageBytes nor any recipient vhost specifies one (FR-2.7).
const defaultMaxMessageBytes = 25 << 20 // 25MiB

// inboundBackend implements go-smtp's Backend for the inbound MTA role
// (FR-2.x). It deliberately does not implement AuthSession: inbound never
// requires authentication (FR-2.1).
type inboundBackend struct {
	cfg Config
}

func (b *inboundBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &inboundSession{
		cfg:        b.cfg,
		clientIP:   remoteIP(c.Conn().RemoteAddr()),
		heloDomain: c.Hostname(),
	}, nil
}

type inboundSession struct {
	cfg        Config
	clientIP   net.IP
	heloDomain string

	from          string
	rcpts         []string
	vhosts        []directory.Vhost // parallel to rcpts
	correlationID string            // NFR-OBS-2, fresh per transaction (see Mail)
}

var _ gosmtp.Session = (*inboundSession)(nil)

func (s *inboundSession) Reset() {
	s.from = ""
	s.rcpts = nil
	s.vhosts = nil
	s.correlationID = ""
}

func (s *inboundSession) Logout() error { return nil }

// Mail applies FR-2.3's per-source-IP and per-envelope-sender rate
// limiting before accepting the envelope sender: over-limit yields a
// temporary 4xx, since the sender just needs to back off and retry, not a
// permanent rejection.
func (s *inboundSession) Mail(from string, _ *gosmtp.MailOptions) error {
	// NFR-OBS-2: one correlation ID per transaction (not per connection —
	// Reset lets one connection carry multiple MAIL/DATA cycles), so this
	// message's own lifecycle is traceable independent of whatever else
	// shares the connection.
	s.correlationID = logging.NewCorrelationID()
	if err := s.checkRateLimit(context.Background(), from); err != nil {
		return err
	}
	s.from = from
	return nil
}

func (s *inboundSession) checkRateLimit(ctx context.Context, from string) error {
	if s.cfg.RateLimiter == nil {
		return nil
	}

	if s.clientIP != nil && s.cfg.RateLimitIPCapacity > 0 {
		allowed, err := s.cfg.RateLimiter.Allow(ctx, "ip:"+s.clientIP.String(), s.cfg.RateLimitIPCapacity, s.cfg.RateLimitIPRefillPerSecond)
		if err == nil && !allowed {
			return tempRateLimitError("source IP")
		}
	}
	if from != "" && s.cfg.RateLimitSenderCapacity > 0 {
		allowed, err := s.cfg.RateLimiter.Allow(ctx, "sender:"+from, s.cfg.RateLimitSenderCapacity, s.cfg.RateLimitSenderRefillPerSecond)
		if err == nil && !allowed {
			return tempRateLimitError("envelope sender")
		}
	}
	return nil
}

func tempRateLimitError(dimension string) error {
	return &gosmtp.SMTPError{
		Code:         450,
		EnhancedCode: gosmtp.EnhancedCode{4, 7, 1},
		Message:      "rate limit exceeded for " + dimension + ", try again later",
	}
}

// Rcpt rejects RCPT TO for domains not present in the Directory with a
// permanent 550, before DATA is ever reached (FR-2.2).
func (s *inboundSession) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	_, domain, ok := directory.ParseAddress(to)
	if !ok {
		return &gosmtp.SMTPError{
			Code:         501,
			EnhancedCode: gosmtp.EnhancedCode{5, 1, 3},
			Message:      "malformed recipient address",
		}
	}
	vhost, ok := s.cfg.Directory.Vhost(context.Background(), domain)
	if !ok || !vhost.Active {
		return &gosmtp.SMTPError{
			Code:         550,
			EnhancedCode: gosmtp.EnhancedCode{5, 1, 1},
			Message:      "no such domain here",
		}
	}
	s.rcpts = append(s.rcpts, to)
	s.vhosts = append(s.vhosts, vhost)
	return nil
}

// Data runs the FR-2.4/2.5 filter pipeline once per transaction (SPF/
// DKIM/DMARC/spam-score are about the sender and content, not any one
// recipient) and stores the message per the resulting verdict: accept ->
// INBOX, quarantine -> a distinct Quarantine mailbox, reject -> no
// storage, permanent 5xx. When recipients belong to vhosts with different
// FR-1.2 thresholds, the strictest (lowest positive) threshold among them
// governs the single accept/quarantine/reject outcome for the whole
// transaction: SMTP's DATA phase only allows one response, so a stricter
// vhost's policy can't be silently waived just because a more permissive
// vhost is also a recipient.
func (s *inboundSession) Data(r io.Reader) error {
	body, err := readBounded(r, s.effectiveMaxBytes())
	if err != nil {
		return err
	}

	// NFR-OBS-2: every log call below (and everything Filter.Evaluate,
	// store, and fireReceived themselves log or persist a correlation ID
	// onto) carries this transaction's ID via logging.WithCorrelationID —
	// "inbound acceptance -> filter verdict -> storage write -> webhook
	// dispatch" traced under one ID.
	ctx := logging.WithCorrelationID(context.Background(), s.correlationID)
	slog.InfoContext(ctx, "inbound message accepted for filtering",
		"from", s.from, "rcpt_count", len(s.rcpts), "size", len(body))

	rejectThreshold, quarantineThreshold := s.effectiveThresholds()

	result := s.cfg.Filter.Evaluate(ctx, filter.Input{
		Body:                body,
		MailFrom:            s.from,
		RcptTo:              s.rcpts,
		ClientIP:            s.clientIP,
		HeloDomain:          s.heloDomain,
		RejectThreshold:     rejectThreshold,
		QuarantineThreshold: quarantineThreshold,
	})
	slog.InfoContext(ctx, "filter verdict", "verdict", result.Verdict, "reason", result.Reason)

	switch result.Verdict {
	case filter.Reject:
		// FR-2.5: reject means no storage and no webhook.
		return &gosmtp.SMTPError{
			Code:         550,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message:      "message rejected: " + result.Reason,
		}
	case filter.Quarantine:
		if err := s.store(ctx, body, "Quarantine"); err != nil {
			return err
		}
		metrics.MessagesReceivedTotal.WithLabelValues("quarantine").Inc()
		s.fireReceived(ctx, true)
		return nil
	default:
		if err := s.store(ctx, body, "INBOX"); err != nil {
			return err
		}
		metrics.MessagesReceivedTotal.WithLabelValues("accept").Inc()
		s.fireReceived(ctx, false)
		return nil
	}
}

// fireReceived enqueues FR-2.5's message.received event (with
// quarantine: true when applicable) once per distinct recipient vhost —
// subscriptions are registered per vhost, so a transaction spanning
// multiple hosted vhosts fires one event per vhost rather than one event
// naming recipients a given vhost's subscriber has no business seeing.
// Enqueue only persists a delivery row (see Config.Webhooks' doc); the
// actual webhook HTTP POST happens later, off this connection entirely.
func (s *inboundSession) fireReceived(ctx context.Context, quarantined bool) {
	if s.cfg.Webhooks == nil {
		return
	}

	recipientsByVhost := make(map[string][]string)
	var vhostOrder []string
	for i, v := range s.vhosts {
		if _, seen := recipientsByVhost[v.Domain]; !seen {
			vhostOrder = append(vhostOrder, v.Domain)
		}
		recipientsByVhost[v.Domain] = append(recipientsByVhost[v.Domain], s.rcpts[i])
	}

	for _, domain := range vhostOrder {
		payload, err := webhook.NewEventPayload(uuid.NewString(), webhook.EventMessageReceived, domain, map[string]any{
			"from": s.from, "to": recipientsByVhost[domain], "quarantine": quarantined,
		})
		if err != nil {
			continue
		}
		_ = s.cfg.Webhooks.Enqueue(ctx, domain, webhook.EventMessageReceived, payload)
	}
}

func (s *inboundSession) store(ctx context.Context, body []byte, folder string) error {
	for i, rcpt := range s.rcpts {
		local, _, ok := directory.ParseAddress(rcpt)
		if !ok {
			continue
		}
		mailbox := directory.MailboxPath(local, folder)
		if _, err := s.cfg.Store.Write(ctx, s.vhosts[i].Domain, mailbox, bytes.NewReader(body)); err != nil {
			return &gosmtp.SMTPError{
				Code:         451,
				EnhancedCode: gosmtp.EnhancedCode{4, 3, 0},
				Message:      "temporary storage failure",
			}
		}
		slog.InfoContext(ctx, "message stored", "vhost", s.vhosts[i].Domain, "mailbox", mailbox)
	}
	return nil
}

func (s *inboundSession) effectiveThresholds() (reject, quarantine float64) {
	for _, v := range s.vhosts {
		reject = minPositive(reject, v.SpamRejectThreshold)
		quarantine = minPositive(quarantine, v.SpamQuarantineThreshold)
	}
	return reject, quarantine
}

func (s *inboundSession) effectiveMaxBytes() int64 {
	limit := s.cfg.MaxMessageBytes
	if limit <= 0 {
		limit = defaultMaxMessageBytes
	}
	for _, v := range s.vhosts {
		if v.MaxMessageBytes > 0 && v.MaxMessageBytes < limit {
			limit = v.MaxMessageBytes
		}
	}
	return limit
}

// minPositive returns whichever of current/candidate is smaller, ignoring
// non-positive values entirely (0 means "no explicit threshold/limit
// configured", not "zero tolerance").
func minPositive(current, candidate float64) float64 {
	if candidate <= 0 {
		return current
	}
	if current <= 0 || candidate < current {
		return candidate
	}
	return current
}

// readBounded reads r fully. go-smtp's own DATA reader already enforces
// Config.MaxMessageBytes mid-stream (see that field's doc): it fails the
// moment the byte count is exceeded, without buffering the rest of the
// message, so a message over that ceiling is genuinely rejected
// mid-transfer (FR-2.7), not after full receipt — io.ReadAll below
// surfaces that failure as soon as go-smtp's reader produces it. A
// recipient vhost's smaller FR-1.2 limit can't be enforced the same way:
// go-smtp has no per-connection dynamic size hook, and the vhost isn't
// known until RCPT, after any SIZE= parameter was already checked against
// the server-wide ceiling — so it's applied here instead, against the
// body go-smtp already bounded (best-effort, post-receipt for that
// tighter per-vhost case specifically).
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, &gosmtp.SMTPError{
			Code:         552,
			EnhancedCode: gosmtp.EnhancedCode{5, 3, 4},
			Message:      "message exceeds maximum size",
		}
	}
	return body, nil
}

func remoteIP(addr net.Addr) net.IP {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
