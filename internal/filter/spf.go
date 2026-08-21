package filter

import (
	"context"
	"net"

	"blitiri.com.ar/go/spf"
)

// SPFResult mirrors blitiri.com.ar/go/spf's Result values (RFC 7208 §8),
// re-exported so callers don't need to import that package directly.
type SPFResult string

var (
	SPFNone      = SPFResult(spf.None)
	SPFNeutral   = SPFResult(spf.Neutral)
	SPFPass      = SPFResult(spf.Pass)
	SPFFail      = SPFResult(spf.Fail)
	SPFSoftFail  = SPFResult(spf.SoftFail)
	SPFTempError = SPFResult(spf.TempError)
	SPFPermError = SPFResult(spf.PermError)
)

// CheckSPF evaluates SPF (RFC 7208) for a message from sender (the
// envelope MAIL FROM address; "" for a null/bounce sender, in which case
// the HELO domain is used instead), received from ip, with the client's
// HELO/EHLO domain helo. resolver may be nil to use real DNS.
func CheckSPF(ctx context.Context, resolver Resolver, ip net.IP, helo, sender string) (SPFResult, error) {
	opts := []spf.Option{spf.WithContext(ctx)}
	if resolver != nil {
		opts = append(opts, spf.WithResolver(resolver))
	}
	result, err := spf.CheckHostWithSender(ip, helo, sender, opts...)
	return SPFResult(result), err
}
