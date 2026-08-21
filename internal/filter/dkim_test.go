package filter_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/isaiahiroko/envelope/internal/filter"
)

func signTestMessage(t *testing.T, key *rsa.PrivateKey, domain, selector string) string {
	t.Helper()
	raw := "From: alice@" + domain + "\r\nTo: bob@remote.test\r\nSubject: hi\r\n\r\nbody\r\n"

	var signed bytes.Buffer
	if err := dkim.Sign(&signed, strings.NewReader(raw), &dkim.SignOptions{
		Domain: domain, Selector: selector, Signer: key,
	}); err != nil {
		t.Fatalf("dkim.Sign: %v", err)
	}
	return signed.String()
}

func dkimDNSRecord(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func TestVerifyDKIMValid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signed := signTestMessage(t, key, "example.test", "envelope")
	r := &fakeResolver{txt: map[string][]string{
		"envelope._domainkey.example.test": {dkimDNSRecord(t, key)},
	}}

	results, err := filter.VerifyDKIM(context.Background(), r, strings.NewReader(signed))
	if err != nil {
		t.Fatalf("VerifyDKIM: %v", err)
	}
	if len(results) != 1 || !results[0].Valid || results[0].Domain != "example.test" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestVerifyDKIMWrongKeyFails(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signed := signTestMessage(t, key, "example.test", "envelope")
	// DNS advertises a different public key than the one that actually
	// signed the message — verification must fail, not silently pass.
	r := &fakeResolver{txt: map[string][]string{
		"envelope._domainkey.example.test": {dkimDNSRecord(t, otherKey)},
	}}

	results, err := filter.VerifyDKIM(context.Background(), r, strings.NewReader(signed))
	if err != nil {
		t.Fatalf("VerifyDKIM: %v", err)
	}
	if len(results) != 1 || results[0].Valid {
		t.Fatalf("expected signature verification to fail, got %+v", results)
	}
}

func TestVerifyDKIMNoSignature(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{}}
	results, err := filter.VerifyDKIM(context.Background(), r, strings.NewReader("From: a@example.test\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatalf("VerifyDKIM: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results for an unsigned message, got %+v", results)
	}
}
