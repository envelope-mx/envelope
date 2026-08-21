package kms_test

import (
	"bytes"
	"testing"

	"github.com/envelope-mx/envelope/internal/kms"
)

func testKey() []byte {
	return bytes.Repeat([]byte("k"), kms.KeySize)
}

func TestEncryptDecryptRoundTrips(t *testing.T) {
	enc, err := kms.NewAESGCMEncryptor(testKey())
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}

	plaintext := []byte("-----BEGIN RSA PRIVATE KEY-----\nfake key material\n-----END RSA PRIVATE KEY-----")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	if bytes.Contains(ciphertext, []byte("BEGIN RSA PRIVATE KEY")) {
		t.Fatal("ciphertext must not contain recognizable plaintext substrings")
	}

	got, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesDistinctCiphertextsForSamePlaintext(t *testing.T) {
	enc, err := kms.NewAESGCMEncryptor(testKey())
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}

	plaintext := []byte("same secret every time")
	c1, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	c2, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("expected distinct ciphertexts (distinct nonces) for repeated encryption of the same plaintext")
	}
}

func TestDecryptFailsWithWrongKey(t *testing.T) {
	enc1, _ := kms.NewAESGCMEncryptor(testKey())
	wrongKey := bytes.Repeat([]byte("x"), kms.KeySize)
	enc2, _ := kms.NewAESGCMEncryptor(wrongKey)

	ciphertext, err := enc1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := enc2.Decrypt(ciphertext); err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
}

func TestDecryptFailsOnTamperedCiphertext(t *testing.T) {
	enc, _ := kms.NewAESGCMEncryptor(testKey())
	ciphertext, err := enc.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := enc.Decrypt(tampered); err == nil {
		t.Fatal("expected decryption of tampered ciphertext to fail (GCM authentication)")
	}
}

func TestNewAESGCMEncryptorRejectsWrongKeySize(t *testing.T) {
	if _, err := kms.NewAESGCMEncryptor([]byte("too-short")); err == nil {
		t.Fatal("expected an error for a key that isn't 32 bytes")
	}
}
