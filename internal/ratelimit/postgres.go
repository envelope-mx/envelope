package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/awesome-goose/goose/modules/sql"
	"gorm.io/gorm"
)

// postgresUniqueViolation is Postgres's SQLSTATE code for a unique
// constraint violation.
const postgresUniqueViolation = "23505"

func gormNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == postgresUniqueViolation
}

// bucketRow is the rate_limit_buckets table: one row per limited key
// (e.g. "ip:203.0.113.10" or "sender:alice@example.com").
type bucketRow struct {
	sql.BaseEntity

	Key        string    `gorm:"uniqueIndex;not null"`
	Tokens     float64   `gorm:"not null"`
	LastRefill time.Time `gorm:"column:last_refill;not null"`
}

func (bucketRow) TableName() string { return "rate_limit_buckets" }

// MigratePostgres creates/updates the rate_limit_buckets table.
func MigratePostgres(db *gorm.DB) error {
	return db.AutoMigrate(&bucketRow{})
}

// PostgresLimiter is internal/ratelimit.TokenBucket's math (capacity,
// continuous refill) with state shared across replicas via Postgres
// (FR-2.3), rather than Goose's kv module: kv.KV's fields are populated by
// Goose's DI container during module traversal, but
// internal/platform/smtp's Boot(container) never traverses a module tree
// (TRD §2.1) — the same constraint documented in internal/directory's
// package doc. A row per key, updated under SELECT ... FOR UPDATE, plays
// the same role kv.KV would have.
type PostgresLimiter struct {
	db  *gorm.DB
	now func() time.Time // overridden in tests to avoid real sleeping
}

// NewPostgresLimiter returns a PostgresLimiter backed by db. Callers must
// run MigratePostgres (or internal/storage/migrations.All) first.
func NewPostgresLimiter(db *gorm.DB) *PostgresLimiter {
	return &PostgresLimiter{db: db, now: time.Now}
}

// SetNowFunc overrides the clock Allow uses to compute refill, so tests
// can advance time deterministically instead of sleeping.
func (l *PostgresLimiter) SetNowFunc(now func() time.Time) {
	l.now = now
}

// Allow reports whether a request identified by key is allowed under a
// token bucket with the given capacity, refilled continuously at
// refillPerSecond tokens/second, and consumes a token if so. A key seen
// for the first time starts with a full bucket.
func (l *PostgresLimiter) Allow(ctx context.Context, key string, capacity, refillPerSecond float64) (bool, error) {
	// A brand-new key can race two concurrent first-requests into
	// inserting the same row; the loser's unique-constraint violation is
	// retried, which then takes the update path below.
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		allowed, retry, err := l.tryAllow(ctx, key, capacity, refillPerSecond)
		if !retry {
			return allowed, err
		}
		lastErr = err
	}
	return false, fmt.Errorf("ratelimit: too many conflicting inserts for key %q: %w", key, lastErr)
}

func (l *PostgresLimiter) tryAllow(ctx context.Context, key string, capacity, refillPerSecond float64) (allowed, retry bool, err error) {
	err = l.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row bucketRow
		q := tx.Where("key = ?", key)
		if tx.Dialector.Name() != "sqlite" {
			q = q.Set("gorm:query_option", "FOR UPDATE")
		}
		findErr := q.First(&row).Error

		now := l.now()
		switch {
		case findErr == nil:
			elapsed := now.Sub(row.LastRefill).Seconds()
			if elapsed > 0 {
				row.Tokens += elapsed * refillPerSecond
				if row.Tokens > capacity {
					row.Tokens = capacity
				}
			}
			if row.Tokens < 1 {
				row.LastRefill = now
				allowed = false
			} else {
				row.Tokens--
				row.LastRefill = now
				allowed = true
			}
			return tx.Model(&bucketRow{}).Where("id = ?", row.Id).Updates(map[string]any{
				"tokens": row.Tokens, "last_refill": row.LastRefill,
			}).Error

		case gormNotFound(findErr):
			newRow := bucketRow{Key: key, Tokens: capacity - 1, LastRefill: now}
			allowed = true
			if createErr := tx.Create(&newRow).Error; createErr != nil {
				return createErr
			}
			return nil

		default:
			return findErr
		}
	})

	if err != nil && isUniqueViolation(err) {
		return false, true, err
	}
	return allowed, false, err
}
