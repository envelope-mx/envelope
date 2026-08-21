package memory_test

import (
	"context"
	"testing"

	"github.com/envelope-mx/envelope/internal/directory/memory"
)

func TestAddVhostAndVhostActive(t *testing.T) {
	d := memory.New()
	ctx := context.Background()

	if d.VhostActive(ctx, "example.com") {
		t.Fatal("unregistered vhost should not be active")
	}

	v, err := d.AddVhost("example.com")
	if err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if v.DKIMKey == nil {
		t.Fatalf("unexpected vhost: %+v", v)
	}
	if !d.VhostActive(ctx, "example.com") {
		t.Fatal("expected registered vhost to be active")
	}
}

func TestAddAccountRequiresVhost(t *testing.T) {
	d := memory.New()
	if err := d.AddAccount("example.com", "alice", "s3cret"); err == nil {
		t.Fatal("expected error adding account for unregistered vhost")
	}
}

func TestAuthenticate(t *testing.T) {
	d := memory.New()
	ctx := context.Background()
	if _, err := d.AddVhost("example.com"); err != nil {
		t.Fatalf("AddVhost: %v", err)
	}
	if err := d.AddAccount("example.com", "alice", "s3cret"); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	if !d.Authenticate(ctx, "example.com", "alice", "s3cret") {
		t.Fatal("expected correct credentials to authenticate")
	}
	if d.Authenticate(ctx, "example.com", "alice", "wrong") {
		t.Fatal("expected wrong password to fail")
	}
	if d.Authenticate(ctx, "example.com", "bob", "s3cret") {
		t.Fatal("expected unknown account to fail")
	}
}
