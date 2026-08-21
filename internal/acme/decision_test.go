package acme_test

import (
	"context"
	"testing"

	"github.com/caddyserver/certmagic"

	"github.com/isaiahiroko/envelope/internal/acme"
	"github.com/isaiahiroko/envelope/internal/directory/memory"
)

func TestDecisionFuncSatisfiesCertmagicShape(t *testing.T) {
	// Compile-time proof this is actually pluggable into certmagic, not
	// just shaped similarly by coincidence.
	_ = &certmagic.OnDemandConfig{DecisionFunc: acme.DecisionFunc(memory.New())}
}

func TestDecisionFuncAllowsActiveVhost(t *testing.T) {
	dir := memory.New()
	if _, err := dir.AddVhost("example.test"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}

	if err := acme.DecisionFunc(dir)(context.Background(), "example.test"); err != nil {
		t.Fatalf("expected active vhost to be allowed, got %v", err)
	}
}

func TestDecisionFuncDeniesUnknownDomain(t *testing.T) {
	dir := memory.New()
	if err := acme.DecisionFunc(dir)(context.Background(), "not-a-vhost.test"); err == nil {
		t.Fatal("expected an unregistered domain to be denied")
	}
}
