// Package mailbuild composes a raw, unsigned RFC5322 message from
// structured parts (from/to/subject/text/html/attachments/custom headers)
// — the REST send API's (internal/api.MessageController) equivalent of
// what an SMTP client's DATA payload already looks like when it reaches
// internal/platform/smtp/submission.go's Data handler. Pure MIME
// composition, no business logic (auth, quota, DKIM, storage, queueing all
// stay in the caller) and no dependency on any other internal package, so
// it's independently testable and reusable by any future caller that needs
// to build a message, not just the one that exists today.
package mailbuild

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Attachment is one file attached to a Message.
type Attachment struct {
	Filename, ContentType string
	Content               []byte
}

// Message is the structured input Build renders into raw RFC5322 bytes.
// Bcc is used only to determine recipients at the caller's enqueue step —
// it is never serialized into the composed message's headers, matching
// standard MTA practice. Headers must already have had any collision with
// a header Build writes itself (From, To, Cc, Subject, Date, Message-Id,
// MIME-Version, Content-Type, Content-Transfer-Encoding) rejected by the
// caller — Build does not re-check this.
type Message struct {
	From, Subject, Text, HTML string
	// Domain is used only to build the Message-Id header
	// ("<uuid>@Domain") — the sending vhost's domain, not necessarily
	// what's parseable out of From (which may carry a display name).
	Domain string

	To, Cc, Bcc []string
	Attachments []Attachment
	Headers     map[string]string
}

// reservedHeaders lists the header names Build writes itself — exported so
// a caller can reject a colliding msg.Headers key before ever calling
// Build (see internal/api.MessageController.Send).
var reservedHeaders = map[string]bool{
	"from": true, "to": true, "subject": true, "date": true,
	"message-id": true, "mime-version": true,
	"content-type": true, "content-transfer-encoding": true,
}

// IsReservedHeader reports whether name (case-insensitive) is one Build
// writes itself and therefore cannot appear in Message.Headers.
func IsReservedHeader(name string) bool {
	return reservedHeaders[strings.ToLower(name)]
}

// Build renders msg as raw, unsigned, CRLF-terminated RFC5322 bytes —
// ready for a caller to DKIM-sign and hand to storage.Store.Write, the
// same shape internal/platform/smtp/submission.go's Data handler already
// produces by hand for a raw SMTP-submitted body.
func Build(msg Message) ([]byte, error) {
	bodyContentType, bodyContent, err := buildBodyPart(msg.Text, msg.HTML)
	if err != nil {
		return nil, fmt.Errorf("mailbuild: build body part: %w", err)
	}

	topContentType, topBody := bodyContentType, bodyContent
	if len(msg.Attachments) > 0 {
		topContentType, topBody, err = buildMixed(bodyContentType, bodyContent, msg.Attachments)
		if err != nil {
			return nil, fmt.Errorf("mailbuild: build mixed envelope: %w", err)
		}
	}

	var buf bytes.Buffer
	writeHeader(&buf, "From", msg.From)
	if len(msg.To) > 0 {
		writeHeader(&buf, "To", strings.Join(msg.To, ", "))
	}
	if len(msg.Cc) > 0 {
		writeHeader(&buf, "Cc", strings.Join(msg.Cc, ", "))
	}
	writeHeader(&buf, "Subject", msg.Subject)
	writeHeader(&buf, "Date", time.Now().UTC().Format(time.RFC1123Z))
	writeHeader(&buf, "Message-Id", fmt.Sprintf("<%s@%s>", uuid.NewString(), msg.Domain))
	writeHeader(&buf, "MIME-Version", "1.0")
	for k, v := range msg.Headers {
		writeHeader(&buf, k, v)
	}
	writeHeader(&buf, "Content-Type", topContentType)
	buf.WriteString("\r\n")
	buf.Write(topBody)

	return buf.Bytes(), nil
}

// buildBodyPart returns the sole content-carrying part of the message: a
// multipart/alternative envelope when both text and html are set (text
// first, per RFC 2046's least-preferred-first convention), or a single
// text/plain or text/html part when only one is. Both bodies are written
// as raw UTF-8 with Content-Transfer-Encoding: 8bit (RFC 6152) rather than
// quoted-printable — Go's stdlib mime/quotedprintable has no encoder, only
// a decoder, and hand-rolling one isn't worth it for marginal
// deliverability benefit.
func buildBodyPart(text, html string) (contentType string, body []byte, err error) {
	switch {
	case text != "" && html != "":
		boundary := "ALT_" + uuid.NewString()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		if err := mw.SetBoundary(boundary); err != nil {
			return "", nil, fmt.Errorf("set alternative boundary: %w", err)
		}

		textPart, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {"text/plain; charset=utf-8"},
			"Content-Transfer-Encoding": {"8bit"},
		})
		if err != nil {
			return "", nil, fmt.Errorf("create text/plain part: %w", err)
		}
		textPart.Write([]byte(text))

		htmlPart, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {"text/html; charset=utf-8"},
			"Content-Transfer-Encoding": {"8bit"},
		})
		if err != nil {
			return "", nil, fmt.Errorf("create text/html part: %w", err)
		}
		htmlPart.Write([]byte(html))

		if err := mw.Close(); err != nil {
			return "", nil, fmt.Errorf("close alternative writer: %w", err)
		}
		return fmt.Sprintf("multipart/alternative; boundary=%q", boundary), buf.Bytes(), nil

	case html != "":
		return "text/html; charset=utf-8", []byte(html), nil

	default:
		return "text/plain; charset=utf-8", []byte(text), nil
	}
}

// buildMixed wraps bodyContentType/bodyContent as the first part of an
// outer multipart/mixed envelope, followed by one base64-encoded part per
// attachment.
func buildMixed(bodyContentType string, bodyContent []byte, attachments []Attachment) (contentType string, body []byte, err error) {
	boundary := "MIXED_" + uuid.NewString()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.SetBoundary(boundary); err != nil {
		return "", nil, fmt.Errorf("set mixed boundary: %w", err)
	}

	bodyHeader := textproto.MIMEHeader{"Content-Type": {bodyContentType}}
	if !strings.HasPrefix(bodyContentType, "multipart/") {
		bodyHeader.Set("Content-Transfer-Encoding", "8bit")
	}
	bodyPart, err := mw.CreatePart(bodyHeader)
	if err != nil {
		return "", nil, fmt.Errorf("create mixed body part: %w", err)
	}
	bodyPart.Write(bodyContent)

	for _, a := range attachments {
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		part, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {ct},
			"Content-Disposition":       {fmt.Sprintf("attachment; filename=%q", sanitizeHeaderValue(a.Filename))},
			"Content-Transfer-Encoding": {"base64"},
		})
		if err != nil {
			return "", nil, fmt.Errorf("create attachment part %q: %w", a.Filename, err)
		}
		part.Write([]byte(encodeBase64Wrapped(a.Content)))
	}

	if err := mw.Close(); err != nil {
		return "", nil, fmt.Errorf("close mixed writer: %w", err)
	}
	return fmt.Sprintf("multipart/mixed; boundary=%q", boundary), buf.Bytes(), nil
}

// writeHeader sanitizes value and writes "name: value\r\n" — the same
// shape every hand-written RFC5322 header in this codebase uses (see
// internal/deliverer/bounce.go's buildDSN).
func writeHeader(w *bytes.Buffer, name, value string) {
	fmt.Fprintf(w, "%s: %s\r\n", name, sanitizeHeaderValue(value))
}

// sanitizeHeaderValue strips CR/LF from a value about to be embedded in a
// generated header line, so caller-supplied Subject/From/To/custom header
// content can't inject extra header lines — duplicated verbatim from
// internal/deliverer/bounce.go's unexported function of the same name
// (that package's DSN generation is a fixed, no-attachments structure not
// worth retrofitting onto this package just to share four lines).
func sanitizeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

// encodeBase64Wrapped base64-encodes data and line-wraps it at 76 columns
// (RFC 2045) — encoding/base64's encoders don't line-wrap on their own.
func encodeBase64Wrapped(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var out strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		out.WriteString(encoded[i:end])
		out.WriteString("\r\n")
	}
	return out.String()
}
