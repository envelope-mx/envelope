package filter

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/mail"
	"strings"

	"github.com/emersion/go-msgauth/dmarc"

	"github.com/isaiahiroko/envelope/internal/filter/rspamd"
	"github.com/isaiahiroko/envelope/internal/metrics"
)

// Verdict is the outcome of the FR-2.4/2.5 pipeline: what the SMTP session
// does with the message.
type Verdict string

const (
	Accept     Verdict = "accept"
	Quarantine Verdict = "quarantine"
	Reject     Verdict = "reject"
)

// Result is the full outcome of evaluating a message: the overall Verdict
// plus the signals that produced it (useful for logging and for the SMTP
// rejection text).
type Result struct {
	Verdict    Verdict
	Reason     string
	SPF        SPFResult
	DKIM       []DKIMResult
	DMARC      *dmarc.Record // nil if the From domain has no DMARC policy
	Aligned    bool
	SpamScore  float64
	FailedOpen bool // true if rspamd was unreachable (FR-2.6)
}

// RspamdChecker is the subset of *rspamd.Client's API the pipeline needs —
// an interface so tests can simulate an rspamd outage without a real
// server.
type RspamdChecker interface {
	Check(ctx context.Context, from string, rcpts []string, body io.Reader) (*rspamd.Verdict, error)
}

// Pipeline evaluates FR-2.4/2.5's accept/quarantine/reject verdict for
// inbound messages.
type Pipeline struct {
	// Resolver is nil-able: nil uses real DNS.
	Resolver Resolver
	// Rspamd is required. FR-2.6's fail-open path activates when it
	// returns an error.
	Rspamd RspamdChecker
}

// Input is one message's data for Evaluate.
type Input struct {
	Body       []byte
	MailFrom   string // envelope MAIL FROM; "" for a null/bounce sender
	RcptTo     []string
	ClientIP   net.IP
	HeloDomain string

	// RejectThreshold/QuarantineThreshold are the recipient vhost's FR-1.2
	// policy (directory.Vhost.SpamRejectThreshold/SpamQuarantineThreshold).
	// A zero RejectThreshold is treated as "no reject threshold configured"
	// (never reject on score alone), same for QuarantineThreshold.
	RejectThreshold     float64
	QuarantineThreshold float64
}

// Evaluate runs SPF, DKIM verification, DMARC alignment, and an rspamd
// spam score, then decides accept/quarantine/reject (FR-2.4/2.5).
func (p *Pipeline) Evaluate(ctx context.Context, in Input) Result {
	spfResult, _ := CheckSPF(ctx, p.Resolver, in.ClientIP, in.HeloDomain, in.MailFrom)
	dkimResults, _ := VerifyDKIM(ctx, p.Resolver, bytes.NewReader(in.Body))

	fromDomain := fromHeaderDomain(in.Body)
	var record *dmarc.Record
	aligned := false
	if fromDomain != "" {
		if r, err := LookupDMARC(ctx, p.Resolver, fromDomain); err == nil {
			record = r
		}
	}
	if record != nil {
		if spfResult == SPFPass {
			spfAuthDomain := senderDomain(in.MailFrom, in.HeloDomain)
			aligned = Aligned(spfAuthDomain, fromDomain, record.SPFAlignment)
		}
		if !aligned {
			for _, d := range dkimResults {
				if d.Valid && Aligned(d.Domain, fromDomain, record.DKIMAlignment) {
					aligned = true
					break
				}
			}
		}
	}

	spamScore := 0.0
	failedOpen := false
	if rv, err := p.Rspamd.Check(ctx, in.MailFrom, in.RcptTo, bytes.NewReader(in.Body)); err != nil {
		failedOpen = true
		metrics.SpamScorerUnavailableTotal.Inc()
	} else {
		spamScore = rv.Score
	}

	verdict, reason := decide(record, aligned, spamScore, failedOpen, in.RejectThreshold, in.QuarantineThreshold)

	return Result{
		Verdict: verdict, Reason: reason,
		SPF: spfResult, DKIM: dkimResults, DMARC: record, Aligned: aligned,
		SpamScore: spamScore, FailedOpen: failedOpen,
	}
}

func decide(record *dmarc.Record, aligned bool, spamScore float64, failedOpen bool, rejectThreshold, quarantineThreshold float64) (Verdict, string) {
	if !failedOpen && rejectThreshold > 0 && spamScore >= rejectThreshold {
		return Reject, "spam score at or above reject threshold"
	}
	if record != nil && !aligned && record.Policy == dmarc.PolicyReject {
		return Reject, "DMARC policy=reject and message is not aligned"
	}

	// FR-2.6: rspamd being unreachable never blocks mail outright — it
	// degrades the spam-related portion of the verdict to quarantine
	// rather than being unable to decide. DMARC-driven reject above still
	// applies regardless, since it doesn't depend on rspamd.
	if failedOpen {
		return Quarantine, "rspamd unavailable; failing open to quarantine (FR-2.6)"
	}
	if quarantineThreshold > 0 && spamScore >= quarantineThreshold {
		return Quarantine, "spam score at or above quarantine threshold"
	}
	if record != nil && !aligned && record.Policy == dmarc.PolicyQuarantine {
		return Quarantine, "DMARC policy=quarantine and message is not aligned"
	}

	return Accept, "passed all checks"
}

// fromHeaderDomain extracts the domain of the message's From: header,
// which DMARC alignment (RFC 7489 §3.1) is always measured against.
// Returns "" if the header is missing or unparseable, in which case DMARC
// evaluation is skipped entirely (there's no domain to align against).
func fromHeaderDomain(body []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	addr, err := mail.ParseAddress(msg.Header.Get("From"))
	if err != nil {
		return ""
	}
	return domainOf(addr.Address)
}

// senderDomain is the domain SPF actually authenticated: the MAIL FROM
// domain, or the HELO domain if MAIL FROM was null (RFC 7489 §3.1's SPF
// identity).
func senderDomain(mailFrom, heloDomain string) string {
	if d := domainOf(mailFrom); d != "" {
		return d
	}
	return heloDomain
}

func domainOf(addr string) string {
	_, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return ""
	}
	return domain
}
