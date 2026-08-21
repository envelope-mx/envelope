// Package integration holds cross-package tests that exercise more than
// one of Envelope's custom Goose platforms together. It exists because
// docs/ENVELOPE.md Phase 2's exit criteria requires proving a real,
// end-to-end path — authenticate to submission, DKIM-sign, queue, deliver
// to inbound, retrieve via IMAP — not just each protocol server in
// isolation (that per-package coverage already lives in
// internal/platform/smtp and internal/platform/imap).
package integration_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
	gosasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/isaiahiroko/envelope/internal/directory/memory"
	"github.com/isaiahiroko/envelope/internal/filter"
	"github.com/isaiahiroko/envelope/internal/filter/rspamd"
	"github.com/isaiahiroko/envelope/internal/platform"
	envimap "github.com/isaiahiroko/envelope/internal/platform/imap"
	envsmtp "github.com/isaiahiroko/envelope/internal/platform/smtp"
	"github.com/isaiahiroko/envelope/internal/queue"
	"github.com/isaiahiroko/envelope/internal/storage"
	"github.com/isaiahiroko/envelope/internal/storage/maildir"
)

// noRecordResolver and acceptingRspamd stand in for real DNS/rspamd so
// this test's inbound leg (proving the queued, DKIM-signed body survives
// a second SMTP hop and is retrievable via IMAP — Phase 2's exit
// criterion) isn't gated on the FR-2.4/2.5 verdict pipeline's outcome,
// which internal/filter already tests directly.
type noRecordResolver struct{}

func (noRecordResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (noRecordResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return nil, nil }
func (noRecordResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, nil
}
func (noRecordResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

type acceptingRspamd struct{}

func (acceptingRspamd) Check(context.Context, string, []string, io.Reader) (*rspamd.Verdict, error) {
	return &rspamd.Verdict{Score: 0}, nil
}

func TestSubmissionToInboundToIMAP(t *testing.T) {
	dir := memory.New()
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if err := dir.AddAccount("example.test", "alice", "s3cret"); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	store := maildir.New(t.TempDir())
	q := queue.NewMemoryBackend()

	tlsCfg, err := platform.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatalf("SelfSignedTLSConfig: %v", err)
	}

	inboundAddr := startSMTPRole(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q,
		Filter: &filter.Pipeline{Resolver: noRecordResolver{}, Rspamd: acceptingRspamd{}},
	})
	submissionAddr := startSMTPRole(t, envsmtp.Config{
		Mode: envsmtp.ModeSubmission, Name: "submission", Domain: "mx.example.test",
		TLSConfig: tlsCfg,
		Directory: dir, Store: store, Queue: q,
	})
	imapAddr := startIMAPRole(t, envimap.Config{
		Name: "imap", TLSConfig: tlsCfg, Directory: dir, Store: store,
	})

	// 1. Authenticate to submission (587) and send a message to a mailbox
	// on our own vhost (FR-3.1).
	sc, err := gosmtp.DialStartTLS(submissionAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("DialStartTLS(submission): %v", err)
	}
	defer sc.Close()
	if err := sc.Auth(gosasl.NewPlainClient("", "alice@example.test", "s3cret")); err != nil {
		t.Fatalf("Auth: %v", err)
	}

	const rawMessage = "From: alice@example.test\r\nTo: alice@example.test\r\nSubject: e2e\r\n\r\nhello from submission\r\n"
	if err := sc.SendMail("alice@example.test", []string{"alice@example.test"}, strings.NewReader(rawMessage)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	// 2. The message is now DKIM-signed (FR-3.2) and durably queued
	// (FR-3.3). Verify the queue and DKIM signature directly, the same way
	// internal/platform/smtp's own tests do.
	job, ok, err := q.Dequeue(context.Background())
	if err != nil || !ok {
		t.Fatalf("expected a queued job: ok=%v err=%v", ok, err)
	}
	if job.Vhost != "example.test" || job.To != "alice@example.test" {
		t.Fatalf("unexpected job: %+v", job)
	}

	stagedRef := storage.MessageRef{Vhost: job.Vhost, Mailbox: envsmtp.OutboxMailbox, Key: job.BodyRef}
	stagedBody := readAll(t, store, stagedRef)
	if _, err := dkim.Verify(strings.NewReader(string(stagedBody))); err != nil {
		t.Fatalf("dkim.Verify on staged body: %v", err)
	}

	// 3. Deliver to inbound (25, loopback) — Phase 5 owns the real
	// deliverer (MX lookup, retry, backoff); this drain-and-redeliver step
	// is test-only, standing in for it just enough to prove the queued,
	// DKIM-signed body actually round-trips through a second SMTP hop.
	ic, err := gosmtp.Dial(inboundAddr)
	if err != nil {
		t.Fatalf("Dial(inbound): %v", err)
	}
	defer ic.Close()
	if err := ic.SendMail(job.From, []string{job.To}, strings.NewReader(string(stagedBody))); err != nil {
		t.Fatalf("SendMail(inbound): %v", err)
	}

	// 4. Retrieve via IMAP (993).
	imc, err := imapclient.DialTLS(imapAddr, &imapclient.Options{TLSConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatalf("DialTLS(imap): %v", err)
	}
	defer imc.Close()

	if err := imc.Login("alice@example.test", "s3cret").Wait(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	selectData, err := imc.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if selectData.NumMessages != 1 {
		t.Fatalf("NumMessages = %d, want 1", selectData.NumMessages)
	}

	msgs, err := imc.Fetch(goimap.SeqSetNum(1), &goimap.FetchOptions{
		BodySection: []*goimap.FetchItemBodySection{{}},
	}).Collect()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(msgs) != 1 || len(msgs[0].BodySection) != 1 {
		t.Fatalf("unexpected fetch result: %+v", msgs)
	}

	got := string(msgs[0].BodySection[0].Bytes)
	if !strings.Contains(got, "DKIM-Signature:") {
		t.Fatalf("expected the message retrieved via IMAP to still carry its DKIM signature, got: %s", got)
	}
	if !strings.Contains(got, "hello from submission") {
		t.Fatalf("expected the original body to survive the full round trip, got: %s", got)
	}
}

func readAll(t *testing.T, store storage.Store, ref storage.MessageRef) []byte {
	t.Helper()
	rc, err := store.Read(context.Background(), ref)
	if err != nil {
		t.Fatalf("Read(%+v): %v", ref, err)
	}
	defer rc.Close()

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := rc.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return []byte(buf.String())
}

func startSMTPRole(t *testing.T, cfg envsmtp.Config) string {
	t.Helper()
	cfg.Addr = "127.0.0.1:0"
	p := envsmtp.NewPlatform(cfg)
	app, err := p.Boot(nil)
	if err != nil {
		t.Fatalf("Boot(%s): %v", cfg.Name, err)
	}
	addr := app.(*platform.App).Listener.Addr().String()

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.Run(nil)
	}()
	t.Cleanup(func() {
		app.Shutdown()
		<-done
	})
	return addr
}

func startIMAPRole(t *testing.T, cfg envimap.Config) string {
	t.Helper()
	cfg.Addr = "127.0.0.1:0"
	p := envimap.NewPlatform(cfg)
	app, err := p.Boot(nil)
	if err != nil {
		t.Fatalf("Boot(imap): %v", err)
	}
	addr := app.(*platform.App).Listener.Addr().String()

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.Run(nil)
	}()
	t.Cleanup(func() {
		app.Shutdown()
		<-done
	})
	return addr
}
