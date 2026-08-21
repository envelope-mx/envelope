package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/awesome-goose/goose/modules/sql"
	"gorm.io/gorm"
)

// jobRow is the queue_jobs table. Embeds sql.BaseEntity for
// Id/CreatedAt/UpdatedAt/DeletedAt (TRD §7 outbound_jobs).
type jobRow struct {
	sql.BaseEntity

	Vhost         string    `gorm:"not null;index"`
	From          string    `gorm:"column:from_address;not null"`
	To            string    `gorm:"column:to_address;not null"`
	BodyRef       string    `gorm:"not null"`
	Attempts      int       `gorm:"not null;default:0"`
	NextAttemptAt time.Time `gorm:"not null;index"`
	LastError     string
	Claimed       bool   `gorm:"not null;default:false;index"`
	CorrelationID string `gorm:"column:correlation_id"`
}

func (jobRow) TableName() string { return "queue_jobs" }

// MigratePostgres creates/updates the queue_jobs table.
func MigratePostgres(db *gorm.DB) error {
	return db.AutoMigrate(&jobRow{})
}

// PostgresBackend is the durable Backend implementation (FR-3.3, NFR-AV-2:
// jobs survive a process restart because they live in Postgres, not
// process memory). Concurrent Dequeue callers are serialized via
// `SELECT ... FOR UPDATE SKIP LOCKED` so two workers never claim the same
// job, mirroring the pattern Goose's own queues module uses internally.
type PostgresBackend struct {
	db *gorm.DB
}

// NewPostgresBackend returns a Backend backed by db. Callers must run
// MigratePostgres (or internal/storage/migrations.All) first.
func NewPostgresBackend(db *gorm.DB) *PostgresBackend {
	return &PostgresBackend{db: db}
}

var _ Backend = (*PostgresBackend)(nil)

func (p *PostgresBackend) Enqueue(ctx context.Context, job Job) error {
	if job.ID == "" {
		return fmt.Errorf("queue: job ID is required")
	}
	row := jobRow{
		BaseEntity:    sql.BaseEntity{UUIDAware: sql.UUIDAware{Id: job.ID}},
		Vhost:         job.Vhost,
		From:          job.From,
		To:            job.To,
		BodyRef:       job.BodyRef,
		Attempts:      job.Attempts,
		NextAttemptAt: job.NextAttemptAt,
		LastError:     job.LastError,
		CorrelationID: job.CorrelationID,
	}
	if err := p.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("queue: enqueue job %q: %w", job.ID, err)
	}
	return nil
}

// Dequeue claims the earliest-due unclaimed job whose NextAttemptAt has
// passed, using row-level locking so concurrent callers never claim the
// same job twice.
func (p *PostgresBackend) Dequeue(ctx context.Context) (Job, bool, error) {
	var claimed jobRow
	found := false

	err := p.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row jobRow
		lockHint := " FOR UPDATE SKIP LOCKED"
		if tx.Dialector.Name() == "sqlite" {
			lockHint = "" // SQLite serializes write transactions; the hint isn't accepted.
		}

		result := tx.Raw(
			`SELECT * FROM "queue_jobs" WHERE claimed = ? AND next_attempt_at <= ? AND deleted_at IS NULL `+
				`ORDER BY next_attempt_at ASC LIMIT 1`+lockHint,
			false, time.Now(),
		).Scan(&row)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}

		if err := tx.Model(&jobRow{}).Where("id = ?", row.Id).Update("claimed", true).Error; err != nil {
			return err
		}
		row.Claimed = true
		claimed = row
		found = true
		return nil
	})
	if err != nil {
		return Job{}, false, fmt.Errorf("queue: dequeue: %w", err)
	}
	if !found {
		return Job{}, false, nil
	}

	return Job{
		ID: claimed.Id, Vhost: claimed.Vhost, From: claimed.From, To: claimed.To,
		BodyRef: claimed.BodyRef, Attempts: claimed.Attempts,
		NextAttemptAt: claimed.NextAttemptAt, LastError: claimed.LastError,
		CorrelationID: claimed.CorrelationID,
	}, true, nil
}

func (p *PostgresBackend) Count(ctx context.Context) (int, error) {
	var count int64
	if err := p.db.WithContext(ctx).Model(&jobRow{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("queue: count: %w", err)
	}
	return int(count), nil
}

func (p *PostgresBackend) Complete(ctx context.Context, id string) error {
	result := p.db.WithContext(ctx).Delete(&jobRow{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("queue: complete job %q: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("queue: job %q not found", id)
	}
	return nil
}

func (p *PostgresBackend) Fail(ctx context.Context, id string, cause error, nextAttemptAt time.Time) error {
	updates := map[string]any{
		"claimed":         false,
		"next_attempt_at": nextAttemptAt,
		"attempts":        gorm.Expr("attempts + 1"),
	}
	if cause != nil {
		updates["last_error"] = cause.Error()
	}

	result := p.db.WithContext(ctx).Model(&jobRow{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("queue: fail job %q: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("queue: job %q not found", id)
	}
	return nil
}
