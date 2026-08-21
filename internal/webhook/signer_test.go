package webhook_test

import (
	"testing"

	"github.com/isaiahiroko/envelope/internal/webhook"
)

// Known-answer test: RFC 4231 test case 2 (HMAC-SHA256, key "Jefe").
func TestSignKnownAnswer(t *testing.T) {
	const (
		secret = "Jefe"
		body   = "what do ya want for nothing?"
		want   = "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
	)

	got := webhook.Sign(secret, []byte(body))
	if got != want {
		t.Fatalf("Sign() = %q, want %q", got, want)
	}
}

func TestVerifyAcceptsValidSignature(t *testing.T) {
	sig := webhook.Sign("s3cret", []byte("payload"))
	if !webhook.Verify("s3cret", []byte("payload"), sig) {
		t.Fatal("expected Verify to accept a signature Sign produced")
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	sig := webhook.Sign("s3cret", []byte("payload"))
	if webhook.Verify("s3cret", []byte("tampered"), sig) {
		t.Fatal("expected Verify to reject a signature for a different body")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	sig := webhook.Sign("s3cret", []byte("payload"))
	if webhook.Verify("wrong-secret", []byte("payload"), sig) {
		t.Fatal("expected Verify to reject a signature made with a different secret")
	}
}
