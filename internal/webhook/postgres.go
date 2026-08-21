package webhook

import (
	"context"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/awesome-goose/goose/modules/sql"
	"gorm.io/gorm"

	"github.com/isaiahiroko/envelope/internal/kms"
)

// DefaultPageSize/MaxPageSize bound ListSubscriptionsPage/ListAttemptsPage
// (FR-5.4) — the same values and reasoning as
// directory.DefaultVhostPageSize/MaxVhostPageSize, just declared separately
// since this is a different package.
const (
	DefaultPageSize = 100
	MaxPageSize     = 500
)

func pageLimit(limit int) int {
	if limit <= 0 {
		return DefaultPageSize
	}
	if limit > MaxPageSize {
		return MaxPageSize
	}
	return limit
}

// subscriptionRow is the webhook_subscriptions table (TRD §7).
type subscriptionRow struct {
	sql.BaseEntity

	Vhost      string `gorm:"not null;index"`
	URL        string `gorm:"not null"`
	Secret     string `gorm:"not null"`
	EventTypes string `gorm:"column:event_types;not null"` // comma-joined; see encode/decodeEventTypes
	Disabled   bool   `gorm:"not null;default:false"`
}

func (subscriptionRow) TableName() string { return "webhook_subscriptions" }

// deliveryAttemptRow is the webhook_delivery_attempts table (TRD §7). Vhost
// is denormalized from the Subscription so ListAttempts can filter on it
// directly (FR-1.5) without a join.
type deliveryAttemptRow struct {
	sql.BaseEntity

	Vhost          string    `gorm:"not null;index"`
	SubscriptionID string    `gorm:"column:subscription_id;not null;index"`
	EventID        string    `gorm:"column:event_id;not null"`
	Attempt        int       `gorm:"not null"`
	StatusCode     int       `gorm:"column:status_code"`
	Error          string    `gorm:""`
	AttemptedAt    time.Time `gorm:"column:attempted_at;not null"`
	Payload        []byte    `gorm:"type:bytea"`
	EventType      string    `gorm:"column:event_type"`
}

func (deliveryAttemptRow) TableName() string { return "webhook_delivery_attempts" }

// MigratePostgres creates/updates the webhook_subscriptions,
// webhook_delivery_attempts, and webhook_deliveries tables.
func MigratePostgres(db *gorm.DB) error {
	return db.AutoMigrate(&subscriptionRow{}, &deliveryAttemptRow{}, &deliveryJobRow{})
}

// PostgresStore is the durable Store implementation (FR-6.5).
type PostgresStore struct {
	db  *gorm.DB
	enc kms.Encryptor
}

// NewPostgresStore returns a Store backed by db, encrypting subscription
// signing secrets at rest via enc (TRD R1, NFR-SEC-3 — see
// internal/kms's package doc, and internal/directory.New's doc for why
// enc is a required, not optional, parameter). Callers must run
// MigratePostgres (or internal/storage/migrations.All) first.
func NewPostgresStore(db *gorm.DB, enc kms.Encryptor) *PostgresStore {
	return &PostgresStore{db: db, enc: enc}
}

var _ Store = (*PostgresStore)(nil)

func (p *PostgresStore) CreateSubscription(ctx context.Context, sub Subscription) error {
	if sub.ID == "" {
		return fmt.Errorf("webhook: subscription ID is required")
	}
	encryptedSecret, err := p.encryptSecret(sub.Secret)
	if err != nil {
		return fmt.Errorf("webhook: encrypt secret for subscription %q: %w", sub.ID, err)
	}
	row := subscriptionRow{
		BaseEntity: sql.BaseEntity{UUIDAware: sql.UUIDAware{Id: sub.ID}},
		Vhost:      sub.Vhost,
		URL:        sub.URL,
		Secret:     encryptedSecret,
		EventTypes: encodeEventTypes(sub.EventTypes),
		Disabled:   sub.Disabled,
	}
	if err := p.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("webhook: create subscription %q: %w", sub.ID, err)
	}
	return nil
}

func (p *PostgresStore) ListSubscriptions(ctx context.Context, vhost string) ([]Subscription, error) {
	var rows []subscriptionRow
	if err := p.db.WithContext(ctx).Where("vhost = ?", vhost).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("webhook: list subscriptions for vhost %q: %w", vhost, err)
	}
	out := make([]Subscription, len(rows))
	for i, r := range rows {
		sub, err := p.subscriptionFromRow(r)
		if err != nil {
			return nil, fmt.Errorf("webhook: decrypt secret for subscription %q: %w", r.Id, err)
		}
		out[i] = sub
	}
	return out, nil
}

func (p *PostgresStore) ListSubscriptionsPage(ctx context.Context, vhost, cursor string, limit int) ([]Subscription, error) {
	q := p.db.WithContext(ctx).Where("vhost = ?", vhost).Order("id ASC").Limit(pageLimit(limit))
	if cursor != "" {
		q = q.Where("id > ?", cursor)
	}

	var rows []subscriptionRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("webhook: list subscriptions for vhost %q: %w", vhost, err)
	}
	out := make([]Subscription, len(rows))
	for i, r := range rows {
		sub, err := p.subscriptionFromRow(r)
		if err != nil {
			return nil, fmt.Errorf("webhook: decrypt secret for subscription %q: %w", r.Id, err)
		}
		out[i] = sub
	}
	return out, nil
}

// encryptSecret/decryptSecret apply TRD R1's at-rest encryption
// (internal/kms) to a subscription's HMAC signing secret — see
// internal/directory.Service's encryptPEM/decryptPEM for the identical
// pattern applied to DKIM keys.
func (p *PostgresStore) encryptSecret(secret string) (string, error) {
	ciphertext, err := p.enc.Encrypt([]byte(secret))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (p *PostgresStore) decryptSecret(stored string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return "", fmt.Errorf("decode stored ciphertext: %w", err)
	}
	plaintext, err := p.enc.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// RotateSecrets re-encrypts every subscription's signing secret from
// oldEnc to newEnc — the webhook half of docs/RUNBOOK.md §4.7's key
// rotation (see directory.Service.RotateDKIMKeys for the DKIM half; the
// resumability and no-concurrent-app-process caveats there apply
// identically here). See cmd/envelope/main.go's --rotate-master-key.
func (p *PostgresStore) RotateSecrets(ctx context.Context, oldEnc, newEnc kms.Encryptor) (rotated int, err error) {
	var rows []subscriptionRow
	if err := p.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return 0, fmt.Errorf("webhook: list subscriptions for rotation: %w", err)
	}

	for _, row := range rows {
		ciphertext, err := base64.StdEncoding.DecodeString(row.Secret)
		if err != nil {
			return rotated, fmt.Errorf("webhook: decode stored ciphertext for subscription %q: %w", row.Id, err)
		}

		plaintext, err := oldEnc.Decrypt(ciphertext)
		if err != nil {
			if _, err2 := newEnc.Decrypt(ciphertext); err2 == nil {
				continue // already rotated by a prior, interrupted run
			}
			return rotated, fmt.Errorf("webhook: decrypt secret for subscription %q under old key: %w", row.Id, err)
		}

		newCiphertext, err := newEnc.Encrypt(plaintext)
		if err != nil {
			return rotated, fmt.Errorf("webhook: re-encrypt secret for subscription %q under new key: %w", row.Id, err)
		}
		encoded := base64.StdEncoding.EncodeToString(newCiphertext)
		if err := p.db.WithContext(ctx).Model(&subscriptionRow{}).Where("id = ?", row.Id).
			Update("secret", encoded).Error; err != nil {
			return rotated, fmt.Errorf("webhook: write rotated secret for subscription %q: %w", row.Id, err)
		}
		rotated++
	}
	return rotated, nil
}

func (p *PostgresStore) DisableSubscription(ctx context.Context, vhost, id string) error {
	result := p.db.WithContext(ctx).Model(&subscriptionRow{}).
		Where("vhost = ? AND id = ?", vhost, id).Update("disabled", true)
	if result.Error != nil {
		return fmt.Errorf("webhook: disable subscription %q: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("webhook: subscription %q: %w", id, ErrNotFound)
	}
	return nil
}

// RecordAttempt derives Vhost from the subscription itself (rather than
// trusting attempt.Vhost, whatever the caller happened to pass) — the one
// place this denormalization is written, so a caller that gets it wrong or
// leaves it zero can't corrupt FR-1.5's isolation instead of just being a
// caller bug. Subscriptions are never hard-deleted (DisableSubscription is
// a soft flag), so any SubscriptionID that ever completed CreateSubscription
// resolves here.
func (p *PostgresStore) RecordAttempt(ctx context.Context, attempt DeliveryAttempt) error {
	if attempt.SubscriptionID == "" {
		return fmt.Errorf("webhook: attempt subscription ID is required")
	}

	var sub subscriptionRow
	if err := p.db.WithContext(ctx).Select("vhost").First(&sub, "id = ?", attempt.SubscriptionID).Error; err != nil {
		return fmt.Errorf("webhook: record attempt for subscription %q: resolve vhost: %w", attempt.SubscriptionID, err)
	}

	row := deliveryAttemptRow{
		Vhost:          sub.Vhost,
		SubscriptionID: attempt.SubscriptionID,
		EventID:        attempt.EventID,
		Attempt:        attempt.Attempt,
		StatusCode:     attempt.StatusCode,
		Error:          attempt.Error,
		AttemptedAt:    attempt.AttemptedAt,
		Payload:        attempt.Payload,
		EventType:      attempt.EventType,
	}
	if err := p.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("webhook: record attempt for subscription %q: %w", attempt.SubscriptionID, err)
	}
	return nil
}

func (p *PostgresStore) ListAttempts(ctx context.Context, vhost, subscriptionID string) ([]DeliveryAttempt, error) {
	var rows []deliveryAttemptRow
	err := p.db.WithContext(ctx).
		Where("vhost = ? AND subscription_id = ?", vhost, subscriptionID).
		Order("attempted_at ASC, id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("webhook: list attempts for subscription %q: %w", subscriptionID, err)
	}
	out := make([]DeliveryAttempt, len(rows))
	for i, r := range rows {
		out[i] = deliveryAttemptFromRow(r)
	}
	return out, nil
}

func (p *PostgresStore) ListAttemptsPage(ctx context.Context, vhost, subscriptionID, cursor string, limit int) ([]DeliveryAttempt, error) {
	q := p.db.WithContext(ctx).
		Where("vhost = ? AND subscription_id = ?", vhost, subscriptionID).
		Order("attempted_at ASC, id ASC").
		Limit(pageLimit(limit))
	if cursor != "" {
		var after deliveryAttemptRow
		err := p.db.WithContext(ctx).Select("attempted_at", "id").First(&after, "id = ?", cursor).Error
		if err != nil {
			if stderrors.Is(err, gorm.ErrRecordNotFound) {
				return nil, nil // an unknown/stale cursor yields an empty page, not an error
			}
			return nil, fmt.Errorf("webhook: resolve attempts cursor %q: %w", cursor, err)
		}
		q = q.Where("attempted_at > ? OR (attempted_at = ? AND id > ?)", after.AttemptedAt, after.AttemptedAt, after.Id)
	}

	var rows []deliveryAttemptRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("webhook: list attempts for subscription %q: %w", subscriptionID, err)
	}
	out := make([]DeliveryAttempt, len(rows))
	for i, r := range rows {
		out[i] = deliveryAttemptFromRow(r)
	}
	return out, nil
}

func deliveryAttemptFromRow(r deliveryAttemptRow) DeliveryAttempt {
	return DeliveryAttempt{
		ID:    r.Id,
		Vhost: r.Vhost, SubscriptionID: r.SubscriptionID, EventID: r.EventID, Attempt: r.Attempt,
		StatusCode: r.StatusCode, Error: r.Error, AttemptedAt: r.AttemptedAt,
		Payload: r.Payload, EventType: r.EventType,
	}
}

func (p *PostgresStore) subscriptionFromRow(r subscriptionRow) (Subscription, error) {
	secret, err := p.decryptSecret(r.Secret)
	if err != nil {
		return Subscription{}, err
	}
	return Subscription{
		ID: r.Id, Vhost: r.Vhost, URL: r.URL, Secret: secret,
		EventTypes: decodeEventTypes(r.EventTypes), Disabled: r.Disabled,
	}, nil
}

// encodeEventTypes/decodeEventTypes store EventTypes as a comma-joined
// string rather than a Postgres array column, avoiding a dependency on
// gorm's array/pq extensions for what is, at Phase 3's scale, a short list
// with no query-by-element requirement.
func encodeEventTypes(types []string) string {
	return strings.Join(types, ",")
}

func decodeEventTypes(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
