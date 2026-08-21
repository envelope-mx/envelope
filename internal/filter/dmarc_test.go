package filter_test

import (
	"context"
	"testing"

	"github.com/emersion/go-msgauth/dmarc"

	"github.com/isaiahiroko/envelope/internal/filter"
)

func TestLookupDMARCRecord(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.test": {"v=DMARC1; p=reject; aspf=s; adkim=r"},
	}}

	record, err := filter.LookupDMARC(context.Background(), r, "example.test")
	if err != nil {
		t.Fatalf("LookupDMARC: %v", err)
	}
	if record == nil {
		t.Fatal("expected a record, got nil")
	}
	if record.Policy != dmarc.PolicyReject {
		t.Fatalf("Policy = %q, want %q", record.Policy, dmarc.PolicyReject)
	}
	if record.SPFAlignment != dmarc.AlignmentStrict {
		t.Fatalf("SPFAlignment = %q, want strict", record.SPFAlignment)
	}
}

func TestLookupDMARCNoRecord(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{}}

	record, err := filter.LookupDMARC(context.Background(), r, "no-dmarc.test")
	if err != nil {
		t.Fatalf("LookupDMARC: %v", err)
	}
	if record != nil {
		t.Fatalf("expected nil record for a domain with no DMARC policy, got %+v", record)
	}
}

func TestAlignedStrict(t *testing.T) {
	if !filter.Aligned("example.test", "example.test", dmarc.AlignmentStrict) {
		t.Fatal("expected exact match to align under strict mode")
	}
	if filter.Aligned("mail.example.test", "example.test", dmarc.AlignmentStrict) {
		t.Fatal("expected a subdomain to NOT align with its parent under strict mode")
	}
}

func TestAlignedRelaxed(t *testing.T) {
	if !filter.Aligned("mail.example.test", "example.test", dmarc.AlignmentRelaxed) {
		t.Fatal("expected same organizational domain to align under relaxed mode")
	}
	if !filter.Aligned("mail.example.test", "example.test", "") {
		t.Fatal("expected an absent alignment tag to default to relaxed (RFC 7489 §6.3)")
	}
	if filter.Aligned("mail.example.test", "other.test", dmarc.AlignmentRelaxed) {
		t.Fatal("expected different organizational domains to NOT align")
	}
}

func TestAlignedDifferentPublicSuffixOrgDomains(t *testing.T) {
	// co.uk is a public suffix (not a single-label TLD): "a.example.co.uk"
	// and "b.example.co.uk" share the organizational domain
	// "example.co.uk", but "evil.co.uk" does not share it with either —
	// this only passes with real public-suffix-list awareness, not a
	// naive "last two labels" heuristic.
	if !filter.Aligned("a.example.co.uk", "b.example.co.uk", dmarc.AlignmentRelaxed) {
		t.Fatal("expected shared organizational domain under a multi-label public suffix to align")
	}
	if filter.Aligned("evil.co.uk", "example.co.uk", dmarc.AlignmentRelaxed) {
		t.Fatal("expected different organizational domains under a shared public suffix to NOT align")
	}
}
