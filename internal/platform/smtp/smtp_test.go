package smtp_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"

	gosasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/directory/memory"
	"github.com/envelope-mx/envelope/internal/filter"
	"github.com/envelope-mx/envelope/internal/filter/rspamd"
	"github.com/envelope-mx/envelope/internal/platform"
	envsmtp "github.com/envelope-mx/envelope/internal/platform/smtp"
	"github.com/envelope-mx/envelope/internal/queue"
	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/storage/maildir"
)

// noRecordResolver answers every DNS lookup with "not found", so
// SPF/DKIM/DMARC evaluation in these tests (which don't care about the
// filter pipeline's outcome, just that it runs) resolves quickly and
// deterministically instead of hitting real DNS for "example.test".
type noRecordResolver struct{}

func (noRecordResolver) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (noRecordResolver) LookupMX(context.Context, string) ([]*net.MX, error) { return nil, nil }
func (noRecordResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, nil
}
func (noRecordResolver) LookupAddr(context.Context, string) ([]string, error) { return nil, nil }

// acceptingRspamd always reports a clean score, for tests that only care
// that a message reaches storage, not about verdict routing itself.
type acceptingRspamd struct{}

func (acceptingRspamd) Check(context.Context, string, []string, io.Reader) (*rspamd.Verdict, error) {
	return &rspamd.Verdict{Score: 0}, nil
}

func acceptAllFilter() *filter.Pipeline {
	return &filter.Pipeline{Resolver: noRecordResolver{}, Rspamd: acceptingRspamd{}}
}

// startSMTP boots cfg's platform on an OS-assigned loopback port and
// returns its address plus a cleanup func. cfg.Addr is overwritten.
func startSMTP(t *testing.T, cfg envsmtp.Config) string {
	t.Helper()

	cfg.Addr = "127.0.0.1:0"
	p := envsmtp.NewPlatform(cfg)
	app, err := p.Boot(nil)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	appImpl := app.(*platform.App)
	addr := appImpl.Listener.Addr().String()

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

func newTestDeps(t *testing.T) (*memory.Directory, storage.Store, queue.Backend) {
	t.Helper()
	dir := memory.New()
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if err := dir.AddAccount("example.test", "alice", "s3cret"); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	store := maildir.New(t.TempDir())
	q := queue.NewMemoryBackend()
	return dir, store, q
}

func TestInboundRejectsUnknownDomain(t *testing.T) {
	dir, store, q := newTestDeps(t)
	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q,
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Mail("sender@elsewhere.test", nil); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	err = c.Rcpt("bob@no-such-vhost.test", nil)
	if err == nil {
		t.Fatal("expected Rcpt to an unregistered vhost to fail")
	}
	var smtpErr *gosmtp.SMTPError
	if !isSMTPError(err, &smtpErr) || smtpErr.Code != 550 {
		t.Fatalf("expected a 550 SMTPError, got %v", err)
	}
}

func TestInboundAcceptsAndStores(t *testing.T) {
	dir, store, q := newTestDeps(t)
	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q, Filter: acceptAllFilter(),
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	msg := "From: sender@elsewhere.test\r\nTo: alice@example.test\r\nSubject: hi\r\n\r\nbody\r\n"
	if err := c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	metas, err := store.List(context.Background(), "example.test", directory.MailboxPath("alice", "INBOX"))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("expected 1 stored message, got %d", len(metas))
	}
}

func TestSubmissionRefusesUnauthenticated(t *testing.T) {
	dir, store, q := newTestDeps(t)
	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeSubmission, Name: "test-submission", Domain: "mx.example.test",
		AllowInsecureAuth: true,
		Directory:         dir, Store: store, Queue: q,
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	err = c.Mail("alice@example.test", nil)
	if err == nil {
		t.Fatal("expected unauthenticated Mail to be refused")
	}
	var smtpErr *gosmtp.SMTPError
	if !isSMTPError(err, &smtpErr) || smtpErr.Code != 530 {
		t.Fatalf("expected a 530 SMTPError, got %v", err)
	}
}

func TestSubmissionAuthenticatedSignsAndEnqueues(t *testing.T) {
	dir, store, q := newTestDeps(t)
	tlsCfg, err := platform.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatalf("SelfSignedTLSConfig: %v", err)
	}

	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeSubmission, Name: "test-submission", Domain: "mx.example.test",
		TLSConfig: tlsCfg,
		Directory: dir, Store: store, Queue: q,
	})

	c, err := gosmtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("DialStartTLS: %v", err)
	}
	defer c.Close()

	if err := c.Auth(gosasl.NewPlainClient("", "alice@example.test", "s3cret")); err != nil {
		t.Fatalf("Auth: %v", err)
	}

	msg := "From: alice@example.test\r\nTo: bob@remote.test\r\nSubject: hi\r\n\r\nbody\r\n"
	if err := c.SendMail("alice@example.test", []string{"bob@remote.test"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	job, ok, err := q.Dequeue(context.Background())
	if err != nil || !ok {
		t.Fatalf("expected a queued job: ok=%v err=%v", ok, err)
	}
	if job.Vhost != "example.test" || job.From != "alice@example.test" || job.To != "bob@remote.test" || job.BodyRef == "" {
		t.Fatalf("unexpected job: %+v", job)
	}

	rc, err := store.Read(context.Background(), storage.MessageRef{Vhost: "example.test", Mailbox: envsmtp.OutboxMailbox, Key: job.BodyRef})
	if err != nil {
		t.Fatalf("Read staged body: %v", err)
	}
	defer rc.Close()

	buf := make([]byte, 4096)
	n, _ := rc.Read(buf)
	if !strings.Contains(string(buf[:n]), "DKIM-Signature:") {
		t.Fatalf("expected staged body to be DKIM-signed, got: %s", buf[:n])
	}
}

func TestSubmissionAuthRejectsWrongPassword(t *testing.T) {
	dir, store, q := newTestDeps(t)
	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeSubmission, Name: "test-submission", Domain: "mx.example.test",
		AllowInsecureAuth: true,
		Directory:         dir, Store: store, Queue: q,
	})

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Auth(gosasl.NewPlainClient("", "alice@example.test", "wrong")); err == nil {
		t.Fatal("expected Auth with wrong password to fail")
	}
}

func isSMTPError(err error, target **gosmtp.SMTPError) bool {
	se, ok := err.(*gosmtp.SMTPError)
	if !ok {
		return false
	}
	*target = se
	return true
}
