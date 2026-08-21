package webhook

import (
	"context"
	"fmt"
	"time"

	"github.com/awesome-goose/goose/modules/sql"
	"gorm.io/gorm"
)

// deliveryJobRow is the webhook_deliveries table: the durable retry queue
// backing EventQueue (FR-6.3/6.4), distinct from webhook_delivery_attempts
// (deliveryAttemptRow), which is permanent history that outlives a job's
// removal from this table on completion or dead-letter.
type deliveryJobRow struct {
	sql.BaseEntity

	Vhost          string    `gorm:"not null;index"`
	SubscriptionID string    `gorm:"column:subscription_id;not null;index"`
	URL            string    `gorm:"not null"`
	Secret         string    `gorm:"not null"`
	EventID        string    `gorm:"column:event_id;not null"`
	EventType      string    `gorm:"column:event_type;not null"`
	Payload        []byte    `gorm:"type:bytea"`
	Attempts       int       `gorm:"not null;default:0"`
	NextAttemptAt  time.Time `gorm:"column:next_attempt_at;not null;index"`
	LastError      string
	Claimed        bool   `gorm:"not null;default:false;index"`
	CorrelationID  string `gorm:"column:correlation_id"`
}

func (deliveryJobRow) TableName() string { return "webhook_deliveries" }

// PostgresEventQueue is the durable EventQueue implementation, the same
// SELECT-FOR-UPDATE-SKIP-LOCKED claim pattern queue.PostgresBackend uses
// for outbound mail jobs.
type PostgresEventQueue struct {
	db *gorm.DB
}

// NewPostgresEventQueue returns an EventQueue backed by db. Callers must
// run MigratePostgres (or internal/storage/migrations.All) first.
func NewPostgresEventQueue(db *gorm.DB) *PostgresEventQueue {
	return &PostgresEventQueue{db: db}
}

var _ EventQueue = (*PostgresEventQueue)(nil)

func (p *PostgresEventQueue) Enqueue(ctx context.Context, job DeliveryJob) error {
	if job.ID == "" {
		return fmt.Errorf("webhook: delivery job ID is required")
	}
	row := deliveryJobRow{
		BaseEntity:     sql.BaseEntity{UUIDAware: sql.UUIDAware{Id: job.ID}},
		Vhost:          job.Vhost,
		SubscriptionID: job.SubscriptionID,
		URL:            job.URL,
		Secret:         job.Secret,
		EventID:        job.EventID,
		EventType:      job.EventType,
		Payload:        job.Payload,
		Attempts:       job.Attempts,
		NextAttemptAt:  job.NextAttemptAt,
		LastError:      job.LastError,
		CorrelationID:  job.CorrelationID,
	}
	if err := p.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("webhook: enqueue delivery %q: %w", job.ID, err)
	}
	return nil
}

func (p *PostgresEventQueue) Dequeue(ctx context.Context) (DeliveryJob, bool, error) {
	var claimed deliveryJobRow
	found := false

	err := p.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row deliveryJobRow
		lockHint := " FOR UPDATE SKIP LOCKED"
		if tx.Dialector.Name() == "sqlite" {
			lockHint = ""
		}

		result := tx.Raw(
			`SELECT * FROM "webhook_deliveries" WHERE claimed = ? AND next_attempt_at <= ? AND deleted_at IS NULL `+
				`ORDER BY next_attempt_at ASC LIMIT 1`+lockHint,
			false, time.Now(),
		).Scan(&row)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}

		if err := tx.Model(&deliveryJobRow{}).Where("id = ?", row.Id).Update("claimed", true).Error; err != nil {
			return err
		}
		row.Claimed = true
		claimed = row
		found = true
		return nil
	})
	if err != nil {
		return DeliveryJob{}, false, fmt.Errorf("webhook: dequeue delivery: %w", err)
	}
	if !found {
		return DeliveryJob{}, false, nil
	}

	return deliveryJobFromRow(claimed), true, nil
}

func (p *PostgresEventQueue) Complete(ctx context.Context, id string) error {
	result := p.db.WithContext(ctx).Delete(&deliveryJobRow{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("webhook: complete delivery %q: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("webhook: delivery job %q not found", id)
	}
	return nil
}

func (p *PostgresEventQueue) Fail(ctx context.Context, id string, cause error, nextAttemptAt time.Time) error {
	updates := map[string]any{
		"claimed":         false,
		"next_attempt_at": nextAttemptAt,
		"attempts":        gorm.Expr("attempts + 1"),
	}
	if cause != nil {
		updates["last_error"] = cause.Error()
	}

	result := p.db.WithContext(ctx).Model(&deliveryJobRow{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("webhook: fail delivery %q: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("webhook: delivery job %q not found", id)
	}
	return nil
}

func deliveryJobFromRow(r deliveryJobRow) DeliveryJob {
	return DeliveryJob{
		ID: r.Id, Vhost: r.Vhost, SubscriptionID: r.SubscriptionID, URL: r.URL, Secret: r.Secret,
		EventID: r.EventID, EventType: r.EventType, Payload: r.Payload,
		Attempts: r.Attempts, NextAttemptAt: r.NextAttemptAt, LastError: r.LastError,
		CorrelationID: r.CorrelationID,
	}
}
