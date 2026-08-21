package deliverer

import (
	"context"
	"net"
)

// Resolver is the DNS surface the deliverer needs to route outbound mail
// (TRD FR-3.x's "MX lookup"). *net.Resolver satisfies this directly. An
// injectable interface, rather than calling net.DefaultResolver directly,
// so tests can point MX lookups at a local loopback test server instead of
// real DNS.
type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}
