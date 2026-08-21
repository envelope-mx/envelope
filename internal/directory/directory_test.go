package directory_test

import (
	"testing"

	"github.com/isaiahiroko/envelope/internal/directory"
)

func TestParseAddress(t *testing.T) {
	local, domain, ok := directory.ParseAddress("alice@example.com")
	if !ok || local != "alice" || domain != "example.com" {
		t.Fatalf("ParseAddress = %q, %q, %v", local, domain, ok)
	}

	if _, _, ok := directory.ParseAddress("not-an-address"); ok {
		t.Fatal("expected ParseAddress to fail on an address with no @")
	}
}

func TestMailboxPath(t *testing.T) {
	if got := directory.MailboxPath("alice", "INBOX"); got != "alice/INBOX" {
		t.Fatalf("MailboxPath = %q", got)
	}
}
