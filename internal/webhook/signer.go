package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Sign returns the FR-6.2 webhook signature for body under secret, in the
// "sha256=<hex>" form (matching the Stripe/GitHub convention).
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether sig is a valid FR-6.2 signature of body under
// secret. Comparison is constant-time to avoid leaking signature bytes
// through a timing side channel.
func Verify(secret string, body []byte, sig string) bool {
	expected := Sign(secret, body)
	return hmac.Equal([]byte(expected), []byte(sig))
}
