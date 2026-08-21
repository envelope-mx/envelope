// Package dbtest gives Postgres-backed unit tests (internal/directory,
// internal/queue, internal/webhook, internal/storage/postgres) a real
// database connection without making `go test ./...` depend on Postgres
// being available: DB skips the calling test when
// ENVELOPE_TEST_POSTGRES_DSN isn't set, so CI/local runs stay hermetic by
// default and only exercise these tests when a database is deliberately
// provided (e.g. a docker-run Postgres during development, or a Postgres
// service container in CI).
package dbtest

import (
	"fmt"
	"os"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// DSNEnvVar is the environment variable DB reads the Postgres connection
// string from.
const DSNEnvVar = "ENVELOPE_TEST_POSTGRES_DSN"

// DB returns a *gorm.DB connected to the test Postgres instance, or skips
// the test if DSNEnvVar isn't set. Each call opens its own connection;
// tests are responsible for using unique IDs/domains to avoid colliding
// with each other in the shared database.
func DB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := os.Getenv(DSNEnvVar)
	if dsn == "" {
		t.Skipf("%s not set; skipping Postgres-backed test", DSNEnvVar)
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("dbtest: connect: %v", err)
	}
	return db
}

// Truncate empties tables before a test runs, so repeated runs against the
// same long-lived test database don't accumulate rows across invocations.
// Failures are fatal: running against dirty state would be worse than not
// running at all.
func Truncate(t *testing.T, db *gorm.DB, tables ...string) {
	t.Helper()
	for _, table := range tables {
		if err := db.Exec(fmt.Sprintf(`TRUNCATE TABLE %q RESTART IDENTITY CASCADE`, table)).Error; err != nil {
			t.Fatalf("dbtest: truncate %s: %v", table, err)
		}
	}
}
