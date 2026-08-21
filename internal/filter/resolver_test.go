package filter_test

import (
	"context"
	"net"
)

// fakeResolver is a deterministic filter.Resolver for tests: no real DNS
// involved, so SPF/DMARC/DKIM evaluation is reproducible.
type fakeResolver struct {
	txt map[string][]string
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if recs, ok := f.txt[name]; ok {
		return recs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeResolver) LookupMX(_ context.Context, _ string) ([]*net.MX, error) { return nil, nil }

func (f *fakeResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return nil, nil
}

func (f *fakeResolver) LookupAddr(_ context.Context, _ string) ([]string, error) { return nil, nil }
