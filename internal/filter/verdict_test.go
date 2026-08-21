package filter_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/isaiahiroko/envelope/internal/filter"
	"github.com/isaiahiroko/envelope/internal/filter/rspamd"
	"github.com/isaiahiroko/envelope/internal/metrics"
)

type fakeRspamd struct {
	verdict *rspamd.Verdict
	err     error
}

func (f *fakeRspamd) Check(_ context.Context, _ string, _ []string, _ io.Reader) (*rspamd.Verdict, error) {
	return f.verdict, f.err
}

// testMessage is a message body plus a resolver seeded with whatever
// SPF/DKIM/DMARC records the test needs.
type testMessage struct {
	body     string
	resolver *fakeResolver
}

func newSignedMessage(t *testing.T, domain string, spfPass bool, dmarcRecord string) testMessage {
	t.Helper()
	return newMessage(t, domain, true, spfPass, dmarcRecord)
}

// newMessage builds a test message From alice@domain, optionally
// DKIM-signed. dkimSigned must be false to genuinely exercise an
// "unaligned" DMARC scenario: signing with the same domain as the From:
// header makes DKIM trivially aligned (exact domain match) regardless of
// SPF, since DMARC passes if *either* signal aligns.
func newMessage(t *testing.T, domain string, dkimSigned, spfPass bool, dmarcRecord string) testMessage {
	t.Helper()

	raw := "From: alice@" + domain + "\r\nTo: bob@remote.test\r\nSubject: hi\r\n\r\nbody\r\n"
	txt := map[string][]string{}
	body := raw

	if dkimSigned {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		var signed bytes.Buffer
		if err := dkim.Sign(&signed, strings.NewReader(raw), &dkim.SignOptions{
			Domain: domain, Selector: "envelope", Signer: key,
		}); err != nil {
			t.Fatalf("dkim.Sign: %v", err)
		}
		body = signed.String()
		txt["envelope._domainkey."+domain] = []string{dkimDNSRecord(t, key)}
	}

	if spfPass {
		txt[domain] = []string{"v=spf1 ip4:203.0.113.10 -all"}
	} else {
		txt[domain] = []string{"v=spf1 -all"}
	}
	if dmarcRecord != "" {
		txt["_dmarc."+domain] = []string{dmarcRecord}
	}

	return testMessage{body: body, resolver: &fakeResolver{txt: txt}}
}

func newPipeline(t *testing.T, msg testMessage, rspamdVerdict *rspamd.Verdict, rspamdErr error) *filter.Pipeline {
	t.Helper()
	return &filter.Pipeline{
		Resolver: msg.resolver,
		Rspamd:   &fakeRspamd{verdict: rspamdVerdict, err: rspamdErr},
	}
}

func baseInput(msg testMessage) filter.Input {
	return filter.Input{
		Body:                []byte(msg.body),
		MailFrom:            "alice@example.test",
		RcptTo:              []string{"bob@remote.test"},
		ClientIP:            net.ParseIP("203.0.113.10"),
		HeloDomain:          "mail.example.test",
		RejectThreshold:     15,
		QuarantineThreshold: 6,
	}
}

func TestEvaluateAccept(t *testing.T) {
	msg := newSignedMessage(t, "example.test", true, "v=DMARC1; p=reject")
	p := newPipeline(t, msg, &rspamd.Verdict{Score: 1.0}, nil)

	result := p.Evaluate(context.Background(), baseInput(msg))
	if result.Verdict != filter.Accept {
		t.Fatalf("Verdict = %q (%s), want accept", result.Verdict, result.Reason)
	}
	if result.SPF != filter.SPFPass || !result.Aligned {
		t.Fatalf("expected SPF pass + DMARC aligned, got SPF=%q Aligned=%v", result.SPF, result.Aligned)
	}
}

func TestEvaluateRejectsOnSpamScore(t *testing.T) {
	msg := newSignedMessage(t, "example.test", true, "")
	p := newPipeline(t, msg, &rspamd.Verdict{Score: 20.0}, nil)

	result := p.Evaluate(context.Background(), baseInput(msg))
	if result.Verdict != filter.Reject {
		t.Fatalf("Verdict = %q (%s), want reject", result.Verdict, result.Reason)
	}
}

func TestEvaluateQuarantinesOnSpamScore(t *testing.T) {
	msg := newSignedMessage(t, "example.test", true, "")
	p := newPipeline(t, msg, &rspamd.Verdict{Score: 8.0}, nil)

	result := p.Evaluate(context.Background(), baseInput(msg))
	if result.Verdict != filter.Quarantine {
		t.Fatalf("Verdict = %q (%s), want quarantine", result.Verdict, result.Reason)
	}
}

func TestEvaluateRejectsOnDMARCRejectUnaligned(t *testing.T) {
	// SPF fails (wrong IP setup) and DKIM domain won't align because the
	// From: domain differs from the signing/SPF domain.
	msg := newMessage(t, "example.test", false, false, "v=DMARC1; p=reject")
	input := baseInput(msg)
	input.ClientIP = net.ParseIP("198.51.100.1") // doesn't match the SPF record's ip4
	p := newPipeline(t, msg, &rspamd.Verdict{Score: 0.0}, nil)

	result := p.Evaluate(context.Background(), input)
	if result.Verdict != filter.Reject {
		t.Fatalf("Verdict = %q (%s), want reject", result.Verdict, result.Reason)
	}
	if result.Aligned {
		t.Fatal("expected message to be unaligned")
	}
}

func TestEvaluateQuarantinesOnDMARCQuarantineUnaligned(t *testing.T) {
	msg := newMessage(t, "example.test", false, false, "v=DMARC1; p=quarantine")
	input := baseInput(msg)
	input.ClientIP = net.ParseIP("198.51.100.1")
	p := newPipeline(t, msg, &rspamd.Verdict{Score: 0.0}, nil)

	result := p.Evaluate(context.Background(), input)
	if result.Verdict != filter.Quarantine {
		t.Fatalf("Verdict = %q (%s), want quarantine", result.Verdict, result.Reason)
	}
}

func TestEvaluateFailsOpenOnRspamdOutage(t *testing.T) {
	msg := newSignedMessage(t, "example.test", true, "")
	before := testutil.ToFloat64(metrics.SpamScorerUnavailableTotal)

	p := newPipeline(t, msg, nil, errors.New("connection refused"))
	result := p.Evaluate(context.Background(), baseInput(msg))

	if result.Verdict == filter.Reject {
		t.Fatalf("expected rspamd outage to never produce a blanket reject, got %q", result.Verdict)
	}
	if result.Verdict != filter.Quarantine {
		t.Fatalf("Verdict = %q (%s), want quarantine (FR-2.6 fail-open)", result.Verdict, result.Reason)
	}
	if !result.FailedOpen {
		t.Fatal("expected FailedOpen=true")
	}

	after := testutil.ToFloat64(metrics.SpamScorerUnavailableTotal)
	if after != before+1 {
		t.Fatalf("envelope_spam_scorer_unavailable_total = %v, want %v", after, before+1)
	}
}

func TestEvaluateFailOpenStillRejectsOnDMARC(t *testing.T) {
	// FR-2.6's fail-open only covers the spam-score signal — a hard DMARC
	// p=reject failure must still reject even during an rspamd outage.
	msg := newMessage(t, "example.test", false, false, "v=DMARC1; p=reject")
	input := baseInput(msg)
	input.ClientIP = net.ParseIP("198.51.100.1")
	p := newPipeline(t, msg, nil, errors.New("timeout"))

	result := p.Evaluate(context.Background(), input)
	if result.Verdict != filter.Reject {
		t.Fatalf("Verdict = %q (%s), want reject even during rspamd outage", result.Verdict, result.Reason)
	}
}
