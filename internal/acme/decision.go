// Package acme adapts Envelope's Directory to certmagic's on-demand TLS
// decision hook (TRD FR-1.3, §9). Wired into cmd/envelope/main.go's
// acmeTLSConfig, which activates in place of the Phase 2 self-signed cert
// helper whenever ENVELOPE_ACME_EMAIL is set:
//
//	cfg := certmagic.NewDefault()
//	cfg.OnDemand = &certmagic.OnDemandConfig{DecisionFunc: acme.DecisionFunc(dir)}
//	tlsConfig := cfg.TLSConfig()
//
// Live-issuing traffic against a real ACME CA still needs a reachable
// port 80 (HTTP-01, certmagic's default challenge — see acmeTLSConfig's
// doc) and real public DNS for the vhost's domain, neither of which holds
// in a dev/CI environment — DecisionFunc itself is unit-tested here
// against a real Directory, and acmeTLSConfig's own test proves the
// certmagic wiring constructs a valid *tls.Config, but neither reaches a
// live CA. Confirmed empirically against the real running binary: a real
// TLS handshake for a domain DecisionFunc denies fails fast (a TLS alert,
// no attempt to contact the CA) rather than hanging or silently allowing
// it.
package acme

import (
	"context"
	"fmt"

	"github.com/isaiahiroko/envelope/internal/directory"
)

// DecisionFunc returns a certmagic OnDemandConfig.DecisionFunc that only
// allows certificate issuance/renewal for domains registered as active
// vhosts in dir. Without this gate, on-demand TLS would issue (and pay
// ACME rate-limit budget for) a certificate for *any* SNI name a client
// asks for — including ones with no relationship to Envelope at all.
func DecisionFunc(dir directory.Directory) func(ctx context.Context, name string) error {
	return func(ctx context.Context, name string) error {
		if !dir.VhostActive(ctx, name) {
			return fmt.Errorf("acme: %q is not a registered, active vhost", name)
		}
		return nil
	}
}
