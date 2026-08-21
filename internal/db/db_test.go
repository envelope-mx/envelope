package db_test

import (
	"os"
	"strings"
	"testing"

	envdb "github.com/envelope-mx/envelope/internal/db"
)

// clearEnv resets every ENVELOPE_DB_* var this file touches, restoring the
// original values after the test — these tests would otherwise be
// order-dependent on whatever the real dev/CI environment happens to have
// set.
func clearEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"ENVELOPE_DB_DSN", "ENVELOPE_DB_HOST", "ENVELOPE_DB_PORT",
		"ENVELOPE_DB_USER", "ENVELOPE_DB_PASSWORD", "ENVELOPE_DB_NAME", "ENVELOPE_DB_SSLMODE",
		"ENVELOPE_DB_USER_API", "ENVELOPE_DB_PASSWORD_API",
		"ENVELOPE_DB_USER_SMTP_INBOUND", "ENVELOPE_DB_PASSWORD_SMTP_INBOUND",
		"ENVELOPE_DB_USER_MIGRATOR", "ENVELOPE_DB_PASSWORD_MIGRATOR",
	}
	for _, k := range keys {
		orig, had := os.LookupEnv(k)
		os.Unsetenv(k)
		t.Cleanup(func() {
			if had {
				os.Setenv(k, orig)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

func TestDSNForRoleFallsBackToSharedCredentialWhenUnset(t *testing.T) {
	clearEnv(t)
	os.Setenv("ENVELOPE_DB_USER", "shared_user")
	os.Setenv("ENVELOPE_DB_PASSWORD", "shared_pass")

	got := envdb.DSNForRole("smtp-inbound")
	if !strings.Contains(got, "user=shared_user") || !strings.Contains(got, "password=shared_pass") {
		t.Fatalf("expected fallback to shared credential, got %q", got)
	}
}

func TestDSNForRoleUsesRoleSpecificCredentialWhenSet(t *testing.T) {
	clearEnv(t)
	os.Setenv("ENVELOPE_DB_USER", "shared_user")
	os.Setenv("ENVELOPE_DB_PASSWORD", "shared_pass")
	os.Setenv("ENVELOPE_DB_USER_SMTP_INBOUND", "envelope_smtp_inbound")
	os.Setenv("ENVELOPE_DB_PASSWORD_SMTP_INBOUND", "inbound_pass")

	got := envdb.DSNForRole("smtp-inbound")
	if !strings.Contains(got, "user=envelope_smtp_inbound") || !strings.Contains(got, "password=inbound_pass") {
		t.Fatalf("expected the role-specific credential, got %q", got)
	}

	// A different role without its own credential still falls back.
	got = envdb.DSNForRole("api")
	if !strings.Contains(got, "user=shared_user") {
		t.Fatalf("expected api (no role-specific credential set) to fall back, got %q", got)
	}
}

func TestDSNForRoleRequiresBothUserAndPassword(t *testing.T) {
	clearEnv(t)
	os.Setenv("ENVELOPE_DB_USER", "shared_user")
	os.Setenv("ENVELOPE_DB_PASSWORD", "shared_pass")
	// Only the user half set — must not use a role-specific user with the
	// shared password, or vice versa; that pairing was never provisioned
	// together and could silently authenticate as the wrong identity.
	os.Setenv("ENVELOPE_DB_USER_API", "envelope_api")

	got := envdb.DSNForRole("api")
	if !strings.Contains(got, "user=shared_user") {
		t.Fatalf("expected fallback when only half the role-specific pair is set, got %q", got)
	}
}

func TestDSNForRoleMigratorUsesUnderscoredEnvKey(t *testing.T) {
	clearEnv(t)
	os.Setenv("ENVELOPE_DB_USER", "shared_user")
	os.Setenv("ENVELOPE_DB_PASSWORD", "shared_pass")
	os.Setenv("ENVELOPE_DB_USER_MIGRATOR", "envelope_migrator")
	os.Setenv("ENVELOPE_DB_PASSWORD_MIGRATOR", "migrator_pass")

	got := envdb.DSNForRole("migrator")
	if !strings.Contains(got, "user=envelope_migrator") {
		t.Fatalf("expected the migrator credential, got %q", got)
	}
}

func TestDSNForRoleExplicitDSNAlwaysWins(t *testing.T) {
	clearEnv(t)
	os.Setenv("ENVELOPE_DB_DSN", "postgres://explicit-dsn")
	os.Setenv("ENVELOPE_DB_USER_API", "envelope_api")
	os.Setenv("ENVELOPE_DB_PASSWORD_API", "api_pass")

	if got := envdb.DSNForRole("api"); got != "postgres://explicit-dsn" {
		t.Fatalf("expected ENVELOPE_DB_DSN to override role-specific pieces, got %q", got)
	}
}
