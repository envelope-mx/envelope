package migrations_test

import (
	"testing"

	"github.com/envelope-mx/envelope/internal/dbtest"
	"github.com/envelope-mx/envelope/internal/storage/migrations"
)

func TestAllIsIdempotent(t *testing.T) {
	db := dbtest.DB(t)

	if err := migrations.All(db); err != nil {
		t.Fatalf("All (first run): %v", err)
	}
	// AutoMigrate must be safe to run again against an already-migrated
	// database — this is what lets main.go call it unconditionally on
	// every boot rather than tracking whether it already ran.
	if err := migrations.All(db); err != nil {
		t.Fatalf("All (second run): %v", err)
	}

	for _, table := range []string{"vhosts", "mailboxes", "dkim_keys", "queue_jobs", "webhook_subscriptions", "webhook_delivery_attempts", "webhook_deliveries", "messages", "rate_limit_buckets", "api_tokens", "audit_log"} {
		if !db.Migrator().HasTable(table) {
			t.Errorf("expected table %q to exist after migration", table)
		}
	}
}
