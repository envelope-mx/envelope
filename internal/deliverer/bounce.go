package deliverer

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/queue"
)

// deliverBounce generates a DSN (RFC 3464 multipart/report) for a
// permanently failed or attempts-exhausted job and delivers it back to the
// original envelope sender "when feasible" (FR-3.6): feasible means the
// sender is a mailbox on one of our own hosted vhosts, in which case it's
// written directly into that mailbox's INBOX via storage.Store — no second
// SMTP hop needed, since we already are the mail system that owns that
// mailbox. If the sender isn't a hosted mailbox, this is a no-op: relaying
// bounces out over SMTP to arbitrary senders both risks backscatter abuse
// and would mean recursively re-running this same deliverer against a
// bounce of a bounce, so v1 doesn't attempt it.
func (d *Deliverer) deliverBounce(ctx context.Context, job queue.Job, cause error) {
	local, domain, ok := directory.ParseAddress(job.From)
	if !ok || !d.cfg.Directory.VhostActive(ctx, domain) {
		return
	}

	dsn, err := buildDSN(job, d.cfg.Domain, cause)
	if err != nil {
		return
	}

	mailbox := directory.MailboxPath(local, "INBOX")
	_, _ = d.cfg.Store.Write(ctx, domain, mailbox, bytes.NewReader(dsn))
}

// buildDSN renders a Delivery Status Notification for job as a
// multipart/report message (RFC 3464): a human-readable explanation, a
// machine-parsable message/delivery-status part, and the original
// message's envelope for reference.
func buildDSN(job queue.Job, mtaDomain string, cause error) ([]byte, error) {
	var buf bytes.Buffer
	boundary := "DSN_" + uuid.NewString()

	fmt.Fprintf(&buf, "From: Mail Delivery System <postmaster@%s>\r\n", mtaDomain)
	fmt.Fprintf(&buf, "To: %s\r\n", job.From)
	fmt.Fprintf(&buf, "Subject: Undelivered Mail Returned to Sender\r\n")
	fmt.Fprintf(&buf, "Message-Id: <%s@%s>\r\n", uuid.NewString(), mtaDomain)
	fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/report; report-type=delivery-status; boundary=%q\r\n", boundary)
	buf.WriteString("\r\n")

	mw := multipart.NewWriter(&buf)
	if err := mw.SetBoundary(boundary); err != nil {
		return nil, fmt.Errorf("deliverer: set DSN boundary: %w", err)
	}

	explanation, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
	if err != nil {
		return nil, fmt.Errorf("deliverer: create DSN explanation part: %w", err)
	}
	fmt.Fprintf(explanation,
		"This is an automatically generated Delivery Status Notification.\r\n\r\n"+
			"Delivery to the following recipient failed permanently:\r\n\r\n    %s\r\n\r\n"+
			"Technical details:\r\n%s\r\n",
		job.To, sanitizeHeaderValue(cause.Error()))

	status, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"message/delivery-status"}})
	if err != nil {
		return nil, fmt.Errorf("deliverer: create DSN status part: %w", err)
	}
	fmt.Fprintf(status, "Reporting-MTA: dns;%s\r\n\r\n", mtaDomain)
	fmt.Fprintf(status, "Final-Recipient: rfc822;%s\r\n", job.To)
	fmt.Fprintf(status, "Action: failed\r\n")
	fmt.Fprintf(status, "Status: 5.0.0\r\n")
	fmt.Fprintf(status, "Diagnostic-Code: smtp;%s\r\n", sanitizeHeaderValue(cause.Error()))

	headers, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"message/rfc822-headers"}})
	if err != nil {
		return nil, fmt.Errorf("deliverer: create DSN original-headers part: %w", err)
	}
	fmt.Fprintf(headers, "From: %s\r\nTo: %s\r\n", job.From, job.To)

	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("deliverer: close DSN multipart writer: %w", err)
	}
	return buf.Bytes(), nil
}

// sanitizeHeaderValue strips CR/LF from a value about to be embedded in a
// generated header or header-like line, so an error message that happens
// to contain a newline (e.g. a multi-line SMTP response) can't inject
// extra header lines into the DSN.
func sanitizeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}
