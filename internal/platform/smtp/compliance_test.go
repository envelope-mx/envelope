package smtp_test

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	gosasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/platform"
	envsmtp "github.com/envelope-mx/envelope/internal/platform/smtp"
	"github.com/envelope-mx/envelope/internal/storage"
)

// TestInboundPreservesListUnsubscribeHeaders is NFR-COMP-3's empirical
// proof for the inbound leg: List-Unsubscribe / List-Unsubscribe-Post
// (RFC 8058 one-click unsubscribe) must reach the stored message
// byte-for-byte, not be stripped or rewritten. inboundSession.Data never
// parses MIME headers at all — it reads the raw DATA bytes and writes them
// verbatim to storage.Store — so this test is really pinning down that
// behavior against regression, not working around a risk of it being
// violated today.
func TestInboundPreservesListUnsubscribeHeaders(t *testing.T) {
	dir, store, q := newTestDeps(t)
	addr := startSMTP(t, envsmtp.Config{
		Mode: envsmtp.ModeInbound, Name: "test-inbound", Domain: "mx.example.test",
		Directory: dir, Store: store, Queue: q, Filter: acceptAllFilter(),
	})

	const unsubscribeHeader = "List-Unsubscribe: <https://sender.example/unsub?id=123>, <mailto:unsub@sender.example>\r\n"
	const unsubscribePostHeader = "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
	msg := "From: sender@elsewhere.test\r\nTo: alice@example.test\r\nSubject: newsletter\r\n" +
		unsubscribeHeader + unsubscribePostHeader + "\r\nbody\r\n"

	c, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if err := c.SendMail("sender@elsewhere.test", []string{"alice@example.test"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	got := readStoredMessage(t, store, "example.test", directory.MailboxPath("alice", "INBOX"))
	if !strings.Contains(got, unsubscribeHeader) {
		t.Fatalf("List-Unsubscribe header not preserved verbatim, got: %s", got)
	}
	if !strings.Contains(got, unsubscribePostHeader) {
		t.Fatalf("List-Unsubscribe-Post header not preserved verbatim, got: %s", got)
	}
}

// TestSubmissionPreservesListUnsubscribeHeaders covers the outbound leg:
// DKIM-signing (submissionSession.Data) must add a signature, not alter
// existing headers — dkim.Sign wraps the original body in a new
// MIME-safe envelope but doesn't rewrite header values it doesn't own.
func TestSubmissionPreservesListUnsubscribeHeaders(t *testing.T) {
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

	const unsubscribeHeader = "List-Unsubscribe: <https://sender.example/unsub?id=123>\r\n"
	msg := "From: alice@example.test\r\nTo: bob@remote.test\r\nSubject: newsletter\r\n" +
		unsubscribeHeader + "\r\nbody\r\n"
	if err := c.SendMail("alice@example.test", []string{"bob@remote.test"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	job, ok, err := q.Dequeue(context.Background())
	if err != nil || !ok {
		t.Fatalf("expected a queued job: ok=%v err=%v", ok, err)
	}
	got := readStoredMessage(t, store, "example.test", envsmtp.OutboxMailbox, job.BodyRef)
	if !strings.Contains(got, unsubscribeHeader) {
		t.Fatalf("List-Unsubscribe header not preserved through DKIM signing, got: %s", got)
	}
}

func readStoredMessage(t *testing.T, store storage.Store, vhost, mailbox string, key ...string) string {
	t.Helper()
	ctx := context.Background()

	var ref storage.MessageRef
	if len(key) == 1 {
		ref = storage.MessageRef{Vhost: vhost, Mailbox: mailbox, Key: key[0]}
	} else {
		metas, err := store.List(ctx, vhost, mailbox)
		if err != nil {
			t.Fatalf("List(%s/%s): %v", vhost, mailbox, err)
		}
		if len(metas) != 1 {
			t.Fatalf("expected exactly 1 stored message in %s/%s, got %d", vhost, mailbox, len(metas))
		}
		ref = metas[0].Ref
	}

	rc, err := store.Read(ctx, ref)
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
	return buf.String()
}
