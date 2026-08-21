package filter

import (
	"context"
	"errors"
	"strings"

	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

// LookupDMARC fetches fromDomain's DMARC policy record (the From: header's
// domain, RFC 7489 §6.3). A nil Record with a nil error means no DMARC
// record is published — DMARC doesn't apply to this message, which is not
// a failure.
func LookupDMARC(ctx context.Context, resolver Resolver, fromDomain string) (*dmarc.Record, error) {
	opts := &dmarc.LookupOptions{}
	if resolver != nil {
		opts.LookupTXT = func(domain string) ([]string, error) {
			return resolver.LookupTXT(ctx, domain)
		}
	}

	record, err := dmarc.LookupWithOptions(fromDomain, opts)
	if err != nil {
		if errors.Is(err, dmarc.ErrNoPolicy) {
			return nil, nil
		}
		return nil, err
	}
	return record, nil
}

// Aligned reports whether authDomain (the SPF-authenticated domain, or a
// DKIM signature's d= domain) is aligned with fromDomain (the From: header
// domain) under mode (RFC 7489 §3.1): "strict" requires an exact match;
// anything else (including the empty string — absent "adkim"/"aspf" tags
// default to relaxed per RFC 7489 §6.3) requires only a matching
// organizational domain.
func Aligned(authDomain, fromDomain string, mode dmarc.AlignmentMode) bool {
	authDomain, fromDomain = strings.ToLower(authDomain), strings.ToLower(fromDomain)
	if authDomain == fromDomain {
		return true
	}
	if mode == dmarc.AlignmentStrict {
		return false
	}

	authOrg, err1 := publicsuffix.EffectiveTLDPlusOne(authDomain)
	fromOrg, err2 := publicsuffix.EffectiveTLDPlusOne(fromDomain)
	return err1 == nil && err2 == nil && authOrg == fromOrg
}
