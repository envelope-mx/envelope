// Package filter runs the inbound accept/quarantine/reject pipeline (TRD
// FR-2.4/FR-2.5): SPF, DKIM verification, DMARC alignment, and an rspamd
// spam score, evaluated against a vhost's configured thresholds.
package filter

import (
	"context"
	"net"
)

// Resolver is the DNS surface SPF and DMARC evaluation need. It's
// intentionally compatible with *net.Resolver (see
// blitiri.com.ar/go/spf.DNSResolver, which *net.Resolver also satisfies),
// so production code passes net.DefaultResolver directly; tests inject a
// fake for deterministic SPF/DMARC record lookups instead of hitting real
// DNS.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}
