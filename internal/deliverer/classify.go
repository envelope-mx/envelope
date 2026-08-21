package deliverer

import (
	"errors"
	"fmt"
	"net"

	gosmtp "github.com/emersion/go-smtp"
)

// deliveryError tags an error as permanent (5xx-equivalent: dead-letter
// immediately, FR-3.4) or temporary (4xx-equivalent or transport-level:
// eligible for backoff retry), the classification FR-3.4/3.6 both key off.
type deliveryError struct {
	err       error
	permanent bool
}

func (e *deliveryError) Error() string { return e.err.Error() }
func (e *deliveryError) Unwrap() error { return e.err }

func permanentErr(err error) error { return &deliveryError{err: err, permanent: true} }
func temporaryErr(err error) error { return &deliveryError{err: err, permanent: false} }

// isPermanent reports whether err should dead-letter immediately without
// retrying (FR-3.4). An *SMTPError classifies by its code (5xx permanent,
// 4xx temporary, matching go-smtp's own SMTPError.Temporary()); anything
// already tagged via permanentErr/temporaryErr uses that tag directly.
// Everything else — dial failures, timeouts, TLS handshake errors — is
// treated as temporary: retrying a possibly-transient network failure is
// safer than bouncing a message that might succeed a minute later.
func isPermanent(err error) bool {
	var de *deliveryError
	if errors.As(err, &de) {
		return de.permanent
	}
	var smtpErr *gosmtp.SMTPError
	if errors.As(err, &smtpErr) {
		return !smtpErr.Temporary()
	}
	return false
}

// classifySMTPErr wraps err (as returned by a *gosmtp.Client call) with
// stage context and the correct permanent/temporary tag.
func classifySMTPErr(stage string, err error) error {
	var smtpErr *gosmtp.SMTPError
	if errors.As(err, &smtpErr) {
		wrapped := fmt.Errorf("deliverer: %s: %w", stage, smtpErr)
		if smtpErr.Temporary() {
			return temporaryErr(wrapped)
		}
		return permanentErr(wrapped)
	}
	return temporaryErr(fmt.Errorf("deliverer: %s: %w", stage, err))
}

// isNotFoundDNSError reports whether err represents an authoritative
// "no such name" answer (NXDOMAIN or an empty answer), as opposed to a
// transient resolver failure (timeout, SERVFAIL, network error).
func isNotFoundDNSError(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
