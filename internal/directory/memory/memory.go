// Package memory is a non-durable, in-memory directory.Directory used by
// tests that don't need a real database. It was Phase 2's production
// Directory; Phase 3 demoted it here once internal/directory.Service
// (Postgres-backed) became the real implementation — nothing in
// production wiring uses this package (index/ENVELOPE.md Phase 3 goal:
// "nothing after this phase should touch an in-memory or non-Postgres
// path in production"). Credentials are held in plaintext deliberately:
// this type is throwaway and never persisted to disk.
package memory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/envelope-mx/envelope/internal/directory"
)

// Directory is an in-memory directory.Directory.
type Directory struct {
	mu       sync.RWMutex
	vhosts   map[string]*directory.Vhost
	accounts map[string]account // keyed by "localpart@vhost"
}

type account struct {
	vhost, localPart, password string
}

// New returns an empty Directory.
func New() *Directory {
	return &Directory{
		vhosts:   make(map[string]*directory.Vhost),
		accounts: make(map[string]account),
	}
}

var _ directory.Directory = (*Directory)(nil)

// AddVhost registers domain as an active vhost, generating a fresh DKIM
// key pair under directory.DefaultDKIMSelector.
func (d *Directory) AddVhost(domain string) (*directory.Vhost, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("memory: generate DKIM key for %q: %w", domain, err)
	}

	v := &directory.Vhost{
		Domain:       domain,
		Active:       true,
		DKIMSelector: directory.DefaultDKIMSelector,
		DKIMKey:      key,
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.vhosts[domain] = v
	return v, nil
}

func (d *Directory) Vhost(_ context.Context, domain string) (directory.Vhost, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	v, ok := d.vhosts[domain]
	if !ok {
		return directory.Vhost{}, false
	}
	return *v, true
}

func (d *Directory) VhostActive(ctx context.Context, domain string) bool {
	v, ok := d.Vhost(ctx, domain)
	return ok && v.Active
}

// AddAccount registers a mailbox credential under vhost, which must already
// be registered via AddVhost.
func (d *Directory) AddAccount(vhost, localPart, password string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.vhosts[vhost]; !ok {
		return fmt.Errorf("memory: vhost %q not registered", vhost)
	}
	d.accounts[accountKey(vhost, localPart)] = account{vhost: vhost, localPart: localPart, password: password}
	return nil
}

func (d *Directory) Authenticate(_ context.Context, vhost, localPart, password string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	acct, ok := d.accounts[accountKey(vhost, localPart)]
	return ok && acct.password == password
}

func accountKey(vhost, localPart string) string {
	return localPart + "@" + vhost
}
