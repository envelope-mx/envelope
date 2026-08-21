package deliverer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	gosmtp "github.com/emersion/go-smtp"

	"github.com/isaiahiroko/envelope/internal/queue"
)

// lookupMX resolves domain's MX hosts, sorted by preference (lowest
// first). A confirmed "no such domain"/"no such record" answer is
// permanent (no route will ever exist); any other resolver failure is
// temporary (worth retrying — it may be transient).
func (d *Deliverer) lookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	mxs, err := d.cfg.Resolver.LookupMX(ctx, domain)
	if err != nil {
		if isNotFoundDNSError(err) {
			return nil, permanentErr(fmt.Errorf("deliverer: no MX records for %q: %w", domain, err))
		}
		return nil, temporaryErr(fmt.Errorf("deliverer: MX lookup for %q failed: %w", domain, err))
	}
	if len(mxs) == 0 {
		return nil, permanentErr(fmt.Errorf("deliverer: no MX records for %q", domain))
	}

	sorted := make([]*net.MX, len(mxs))
	copy(sorted, mxs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Pref < sorted[j].Pref })
	return sorted, nil
}

// send attempts delivery against each MX host in preference order, moving
// on to the next host only after a connection-level or temporary failure —
// a permanent rejection (the destination told us definitively "no", e.g. a
// mailbox that doesn't exist) is authoritative regardless of which
// preference host answered it, so it's returned immediately rather than
// trying the same doomed recipient against a lower-preference host.
func (d *Deliverer) send(ctx context.Context, mxs []*net.MX, job queue.Job, body []byte) error {
	var lastErr error
	for _, mx := range mxs {
		err := d.sendToHost(ctx, mx.Host, job, body)
		if err == nil {
			return nil
		}
		lastErr = err
		if isPermanent(err) {
			return err
		}
	}
	return lastErr
}

func (d *Deliverer) sendToHost(ctx context.Context, host string, job queue.Job, body []byte) error {
	addr := net.JoinHostPort(strings.TrimSuffix(host, "."), strconv.Itoa(d.cfg.Port))

	dialCtx, cancel := context.WithTimeout(ctx, d.cfg.DialTimeout)
	defer cancel()

	client, err := d.dial(dialCtx, addr, host)
	if err != nil {
		return temporaryErr(fmt.Errorf("deliverer: connect to %s: %w", addr, err))
	}
	defer client.Close()

	if err := client.Hello(d.cfg.Domain); err != nil {
		return classifySMTPErr("HELO", err)
	}
	if err := client.Mail(job.From, nil); err != nil {
		return classifySMTPErr("MAIL FROM", err)
	}
	if err := client.Rcpt(job.To, nil); err != nil {
		return classifySMTPErr("RCPT TO", err)
	}
	wc, err := client.Data()
	if err != nil {
		return classifySMTPErr("DATA", err)
	}
	if _, err := wc.Write(body); err != nil {
		wc.Close()
		return temporaryErr(fmt.Errorf("deliverer: write message body: %w", err))
	}
	if err := wc.Close(); err != nil {
		return classifySMTPErr("DATA", err)
	}
	_ = client.Quit()
	return nil
}

// dial connects to addr and opportunistically upgrades to STARTTLS,
// falling back to a fresh plaintext connection if the peer doesn't offer
// it (or the handshake fails) — symmetric with FR-2.1's inbound stance
// ("STARTTLS offered, not required") applied to the outbound leg: peer
// MTAs on the real internet aren't guaranteed to support it, and refusing
// to send plaintext would just mean not delivering mail at all.
func (d *Deliverer) dial(ctx context.Context, addr, host string) (*gosmtp.Client, error) {
	var dialer net.Dialer

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// No MinVersion pin here deliberately: NFR-SEC-1's TLS 1.2+ requirement
	// targets listeners we control (submission, IMAP, API) — this is an
	// outbound client connecting to arbitrary third-party remote MTAs we
	// don't control. Pinning MinVersion 1.2 here would turn a legitimate
	// but TLS-1.0/1.1-only remote MTA into a plaintext fallback (see this
	// function's dial doc) instead of an encrypted delivery, which is a
	// worse outcome — matches real-world outbound-MTA practice (Postfix,
	// Exim) of accepting a broad version range specifically because the
	// remote end isn't ours to require a minimum from.
	client, err := gosmtp.NewClientStartTLS(conn, &tls.Config{ServerName: host})
	if err != nil {
		conn2, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			return nil, dialErr
		}
		client = gosmtp.NewClient(conn2)
	}
	return client, nil
}
