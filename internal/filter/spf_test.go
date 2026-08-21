package filter_test

import (
	"context"
	"net"
	"testing"

	"github.com/isaiahiroko/envelope/internal/filter"
)

// blitiri.com.ar/go/spf's CheckHostWithSender documents that its error
// return can be non-nil even on a successful check (it doubles as a trace
// of which mechanism matched) — so these tests assert on the Result only,
// logging err for debugging rather than treating it as fatal.

func TestCheckSPFPass(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"example.test": {"v=spf1 ip4:203.0.113.10 -all"},
	}}

	result, err := filter.CheckSPF(context.Background(), r, net.ParseIP("203.0.113.10"), "mail.example.test", "sender@example.test")
	t.Logf("CheckSPF trace: %v", err)
	if result != filter.SPFPass {
		t.Fatalf("result = %q, want %q", result, filter.SPFPass)
	}
}

func TestCheckSPFFail(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"example.test": {"v=spf1 ip4:203.0.113.10 -all"},
	}}

	result, err := filter.CheckSPF(context.Background(), r, net.ParseIP("198.51.100.99"), "mail.example.test", "sender@example.test")
	t.Logf("CheckSPF trace: %v", err)
	if result != filter.SPFFail {
		t.Fatalf("result = %q, want %q", result, filter.SPFFail)
	}
}

func TestCheckSPFNullSenderUsesHelo(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"mail.example.test": {"v=spf1 ip4:203.0.113.10 -all"},
	}}

	result, err := filter.CheckSPF(context.Background(), r, net.ParseIP("203.0.113.10"), "mail.example.test", "")
	t.Logf("CheckSPF trace: %v", err)
	if result != filter.SPFPass {
		t.Fatalf("result = %q, want %q", result, filter.SPFPass)
	}
}

func TestCheckSPFNoRecord(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{}}

	result, err := filter.CheckSPF(context.Background(), r, net.ParseIP("203.0.113.10"), "mail.example.test", "sender@no-record.test")
	t.Logf("CheckSPF trace: %v", err)
	if result != filter.SPFNone {
		t.Fatalf("result = %q, want %q", result, filter.SPFNone)
	}
}
