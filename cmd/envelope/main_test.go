package main

import (
	"testing"

	"github.com/isaiahiroko/envelope/internal/directory/memory"
)

// TestACMETLSConfigConstructsAValidTLSConfig is acmeTLSConfig's doc-
// referenced test: it can't reach a real ACME CA from this environment
// (needs a real registrable domain with public DNS, per that function's
// doc), so this proves the certmagic wiring itself is correct — a real
// GetCertificate hook comes back, meaning the Issuers/OnDemand
// construction didn't error or panic — not that a live handshake against
// Let's Encrypt succeeds. internal/acme.DecisionFunc's own allow/deny
// logic is unit-tested separately in that package.
func TestACMETLSConfigConstructsAValidTLSConfig(t *testing.T) {
	dir := memory.New()
	if _, err := dir.AddVhost("acme-test.example"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	cfg := acmeTLSConfig(dir, "ops@example.test")
	if cfg == nil {
		t.Fatal("expected a non-nil *tls.Config")
	}
	if cfg.GetCertificate == nil {
		t.Fatal("expected certmagic to wire a GetCertificate hook for on-demand issuance")
	}
}
