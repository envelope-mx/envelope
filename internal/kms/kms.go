// Package kms provides at-rest encryption for sensitive values stored in
// Postgres — DKIM private keys (internal/directory) and webhook signing
// secrets (internal/webhook). This resolves TRD R1 ("DKIM/webhook-secret
// key encryption at rest — mechanism (app-level envelope encryption vs.
// Postgres TDE/KMS integration) not yet decided").
//
// Decision: application-level envelope encryption (AES-256-GCM), not
// Postgres TDE. TDE requires a specific Postgres distribution/extension
// (managed providers' TDE, e.g. RDS/Cloud SQL, or an extension like
// pgcrypto wired into every write path by hand) that isn't guaranteed
// across TRD G7's "runs identically on a single VM, Docker Compose, or
// Kubernetes" deployment targets — application-level encryption works
// identically everywhere Envelope itself runs, with no dependency on
// which Postgres distribution is behind ENVELOPE_DB_DSN.
//
// The master key itself (Encryptor's ENVELOPE_MASTER_KEY-sourced
// implementation, see cmd/envelope/main.go) is the one piece still
// interim: a single static key from an environment variable is adequate
// for a single-node/dev deployment, but production should source it from
// a real secrets manager (Vault, AWS KMS, GCP KMS) with rotation — this
// package's Encryptor interface is exactly the seam that swap happens
// behind, without touching internal/directory or internal/webhook at all.
package kms

// Encryptor encrypts/decrypts values for storage. Implementations must be
// safe for concurrent use.
type Encryptor interface {
	// Encrypt returns ciphertext for plaintext. Called once per write.
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	// Decrypt reverses Encrypt. Called once per read.
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}
