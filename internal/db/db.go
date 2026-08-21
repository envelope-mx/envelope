// Package db opens the shared Postgres connection cmd/envelope hands to
// every Postgres-backed component (internal/directory, internal/queue,
// internal/webhook, internal/storage/postgres). It exists because none of
// those packages go through Goose's sql module (see internal/directory's
// package doc for why) — something has to own DSN construction and
// gorm.Open instead.
package db

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// DSNFromEnv builds a Postgres DSN from ENVELOPE_DB_* environment
// variables, or returns ENVELOPE_DB_DSN directly if set. Defaults match
// config/config.example.yaml / .env.example's local-dev Postgres.
func DSNFromEnv() string {
	if dsn := os.Getenv("ENVELOPE_DB_DSN"); dsn != "" {
		return dsn
	}
	return buildDSN(envOrDefault("ENVELOPE_DB_USER", "envelope"), envOrDefault("ENVELOPE_DB_PASSWORD", "envelope"))
}

// DSNForRole builds a DSN using deploy/postgres/roles.sql's differentiated
// credential for role (NFR-SEC-5) — ENVELOPE_DB_USER_<ROLE> /
// ENVELOPE_DB_PASSWORD_<ROLE>, role uppercased with "-" turned into "_"
// (e.g. "smtp-inbound" -> ENVELOPE_DB_USER_SMTP_INBOUND, "migrator" ->
// ENVELOPE_DB_USER_MIGRATOR) — falling back to DSNFromEnv's shared
// credential when either half of that pair isn't set, so a deployment that
// hasn't provisioned the differentiated roles yet keeps working exactly as
// before this function existed. ENVELOPE_DB_DSN, if set, always wins
// outright over any role-specific pieces, the same as DSNFromEnv.
func DSNForRole(role string) string {
	if dsn := os.Getenv("ENVELOPE_DB_DSN"); dsn != "" {
		return dsn
	}

	envKey := strings.ToUpper(strings.ReplaceAll(role, "-", "_"))
	user := os.Getenv("ENVELOPE_DB_USER_" + envKey)
	password := os.Getenv("ENVELOPE_DB_PASSWORD_" + envKey)
	if user == "" || password == "" {
		return DSNFromEnv()
	}
	return buildDSN(user, password)
}

func buildDSN(user, password string) string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		envOrDefault("ENVELOPE_DB_HOST", "127.0.0.1"),
		envOrDefault("ENVELOPE_DB_PORT", "5432"),
		user, password,
		envOrDefault("ENVELOPE_DB_NAME", "envelope"),
		envOrDefault("ENVELOPE_DB_SSLMODE", "disable"),
	)
}

// Open connects to Postgres at dsn, routing GORM's own internal logging
// (slow queries, genuine errors) through the process's structured JSON
// logger (NFR-OBS-2) at Warn level, with IgnoreRecordNotFoundError set:
// without it, GORM's default logger writes every expected "no row yet"
// lookup (e.g. internal/ratelimit.PostgresLimiter's first-seen-key case) as
// an ERROR-level line — real noise that looks like an incident and isn't
// one (index/RUNBOOK.md §2 names this exact false-alarm risk). This is the
// fix for that, not just a description of it.
func Open(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormLogger()})
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	return db, nil
}

func gormLogger() gormlogger.Interface {
	return gormlogger.New(slogPrintfWriter{}, gormlogger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  gormlogger.Warn,
		IgnoreRecordNotFoundError: true,
	})
}

// slogPrintfWriter adapts gormlogger.Writer's Printf-shaped interface to
// slog.Default() so GORM's own log lines (slow queries, genuine query
// errors) land in the same structured JSON stream as everything else,
// rather than gorm's default plain-text writer bypassing it entirely. Only
// ever called for Warn-level-and-above events (see gormLogger's
// LogLevel: Warn), so this is inherently low-volume, not a firehose of
// per-query noise.
type slogPrintfWriter struct{}

func (slogPrintfWriter) Printf(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...))
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
