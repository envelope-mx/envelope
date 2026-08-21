package platform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// SelfSignedTLSConfig generates an ephemeral, self-signed certificate for
// the given hostnames and returns a *tls.Config serving it.
//
// This is a stand-in for FR-1.3's real per-vhost ACME automation
// (caddyserver/certmagic, TRD §9), which lands with the Phase 3 Directory
// rewrite. Without it, Phase 2 would have no way to exercise STARTTLS
// (FR-2.1) or TLS-gated AUTH (FR-3.1) at all — a self-signed cert lets the
// protocol path be real even though the cert issuance path isn't yet.
func SelfSignedTLSConfig(hostnames ...string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("platform: generate TLS key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("platform: generate certificate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "envelope-dev"},
		DNSNames:              hostnames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("platform: create certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	// NFR-SEC-1: TLS 1.2+ only. Go's zero-value MinVersion permits TLS 1.0,
	// so this must be set explicitly rather than relying on a runtime
	// default that could quietly change.
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
