package filter

import (
	"context"
	"io"

	"github.com/emersion/go-msgauth/dkim"
)

// DKIMResult is one signature's verification outcome, trimmed to what
// DMARC alignment (FR-2.5) needs: the signing domain (d=) and whether the
// signature itself is cryptographically valid.
type DKIMResult struct {
	Domain string
	Valid  bool
}

// VerifyDKIM verifies every DKIM-Signature header on the raw message in r
// (headers + body, as received) and returns one result per signature.
// resolver may be nil to use real DNS.
func VerifyDKIM(ctx context.Context, resolver Resolver, r io.Reader) ([]DKIMResult, error) {
	opts := &dkim.VerifyOptions{}
	if resolver != nil {
		opts.LookupTXT = func(domain string) ([]string, error) {
			return resolver.LookupTXT(ctx, domain)
		}
	}

	verifications, err := dkim.VerifyWithOptions(r, opts)
	if err != nil {
		return nil, err
	}

	results := make([]DKIMResult, len(verifications))
	for i, v := range verifications {
		results[i] = DKIMResult{Domain: v.Domain, Valid: v.Err == nil}
	}
	return results, nil
}
