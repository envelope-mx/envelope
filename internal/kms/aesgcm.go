package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// KeySize is the required master key length: AES-256.
const KeySize = 32

// AESGCMEncryptor implements Encryptor with AES-256-GCM: a fresh random
// nonce per Encrypt call, prepended to the returned ciphertext (the
// standard construction — GCM's nonce isn't secret, only unique-per-key).
type AESGCMEncryptor struct {
	gcm cipher.AEAD
}

// NewAESGCMEncryptor returns an Encryptor using key, which must be exactly
// KeySize (32) bytes.
func NewAESGCMEncryptor(key []byte) (*AESGCMEncryptor, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("kms: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kms: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kms: create GCM: %w", err)
	}
	return &AESGCMEncryptor{gcm: gcm}, nil
}

var _ Encryptor = (*AESGCMEncryptor)(nil)

func (e *AESGCMEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("kms: generate nonce: %w", err)
	}
	return e.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *AESGCMEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("kms: ciphertext shorter than nonce size")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := e.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("kms: decrypt: %w", err)
	}
	return plaintext, nil
}
