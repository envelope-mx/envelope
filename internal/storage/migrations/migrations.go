// Package migrations bootstraps Envelope's Postgres schema: one AutoMigrate
// call per package that owns a table, run in dependency order. TRD §7 asks
// for migration files at this path once the Postgres backend was
// scheduled (Phase 3); this is that bootstrap, expressed as GORM
// AutoMigrate calls rather than hand-written SQL or Goose's Migration/
// Runner types. Runner and its migration-tracking table are only
// constructible via Goose's DI container (their fields are unexported,
// populated by reflection-based injection during module traversal) — the
// same constraint documented in internal/directory's package doc for why
// this whole layer is built on *gorm.DB directly. AutoMigrate's
// CREATE-TABLE/ADD-COLUMN-IF-NOT-EXISTS semantics are idempotent, so
// running this once from main.go before any instance starts (rather than
// racing multiple instances through it concurrently) is sufficient.
package migrations

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/isaiahiroko/envelope/internal/apiauth"
	"github.com/isaiahiroko/envelope/internal/audit"
	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/queue"
	"github.com/isaiahiroko/envelope/internal/ratelimit"
	"github.com/isaiahiroko/envelope/internal/storage/postgres"
	"github.com/isaiahiroko/envelope/internal/webhook"
)

// All migrates every table Envelope's Postgres-backed components own.
func All(db *gorm.DB) error {
	steps := []struct {
		name string
		fn   func(*gorm.DB) error
	}{
		{"directory", directory.Migrate},
		{"queue", queue.MigratePostgres},
		{"webhook", webhook.MigratePostgres},
		{"storage", postgres.Migrate},
		{"ratelimit", ratelimit.MigratePostgres},
		{"apiauth", apiauth.MigratePostgres},
		{"audit", audit.MigratePostgres},
	}

	for _, step := range steps {
		if err := step.fn(db); err != nil {
			return fmt.Errorf("migrations: %s: %w", step.name, err)
		}
	}
	return nil
}
