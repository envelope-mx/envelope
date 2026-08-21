// Package postgres implements storage.Store on Postgres (TRD FR-4.3/4.4):
// the GA minimum storage backend per PRD §11's resolved open question
// (S3/maildir support following post-GA). Suitable for low/medium volume
// where operating a second storage system isn't justified (FR-4.4); the
// documented volume ceiling this implies is TRD risk R3, still open.
package postgres

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/awesome-goose/goose/modules/sql"
	"gorm.io/gorm"

	"github.com/isaiahiroko/envelope/internal/storage"
)

// messageRow is the messages table (TRD §7). Body lives inline here
// (never nullable, unlike the S3 variant of this table in TRD §7, since
// there's no separate object store to defer to for this backend).
type messageRow struct {
	sql.BaseEntity

	Vhost   string `gorm:"not null;index:idx_message_mailbox"`
	Mailbox string `gorm:"not null;index:idx_message_mailbox"`
	Body    []byte `gorm:"not null;type:bytea"`
	Size    int64  `gorm:"not null"`
	Flags   string `gorm:"not null;default:''"` // comma-joined, see internal/webhook's same convention
}

func (messageRow) TableName() string { return "messages" }

// Migrate creates/updates the messages table.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&messageRow{})
}

// Backend implements storage.Store on Postgres.
type Backend struct {
	db *gorm.DB
}

// New returns a Backend backed by db. Callers must run Migrate (or
// internal/storage/migrations.All) first.
func New(db *gorm.DB) *Backend {
	return &Backend{db: db}
}

var _ storage.Store = (*Backend)(nil)

func (b *Backend) Write(ctx context.Context, vhost, mailbox string, body io.Reader) (storage.MessageRef, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return storage.MessageRef{}, fmt.Errorf("postgres: read body: %w", err)
	}

	row := messageRow{Vhost: vhost, Mailbox: mailbox, Body: data, Size: int64(len(data))}
	if err := b.db.WithContext(ctx).Create(&row).Error; err != nil {
		return storage.MessageRef{}, fmt.Errorf("postgres: write message: %w", err)
	}
	return storage.MessageRef{Vhost: vhost, Mailbox: mailbox, Key: row.Id}, nil
}

func (b *Backend) Read(ctx context.Context, ref storage.MessageRef) (io.ReadCloser, error) {
	row, err := b.find(ctx, ref)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(row.Body)), nil
}

func (b *Backend) List(ctx context.Context, vhost, mailbox string) ([]storage.MessageMeta, error) {
	var rows []messageRow
	err := b.db.WithContext(ctx).
		Select("id", "created_at", "vhost", "mailbox", "size", "flags").
		Where("vhost = ? AND mailbox = ?", vhost, mailbox).
		Order("created_at ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("postgres: list %s/%s: %w", vhost, mailbox, err)
	}

	out := make([]storage.MessageMeta, len(rows))
	for i, r := range rows {
		out[i] = storage.MessageMeta{
			Ref:       storage.MessageRef{Vhost: vhost, Mailbox: mailbox, Key: r.Id},
			Size:      r.Size,
			Flags:     decodeFlags(r.Flags),
			CreatedAt: createdAt(r),
		}
	}
	return out, nil
}

// ListVhost enumerates every message stored for vhost, across every
// mailbox — a single indexed query, unlike maildir's ListVhost, which has
// to walk the filesystem since there's no per-vhost index to query instead.
func (b *Backend) ListVhost(ctx context.Context, vhost string) ([]storage.MessageMeta, error) {
	var rows []messageRow
	err := b.db.WithContext(ctx).
		Select("id", "created_at", "vhost", "mailbox", "size", "flags").
		Where("vhost = ?", vhost).
		Order("created_at ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("postgres: list vhost %s: %w", vhost, err)
	}

	out := make([]storage.MessageMeta, len(rows))
	for i, r := range rows {
		out[i] = storage.MessageMeta{
			Ref:       storage.MessageRef{Vhost: vhost, Mailbox: r.Mailbox, Key: r.Id},
			Size:      r.Size,
			Flags:     decodeFlags(r.Flags),
			CreatedAt: createdAt(r),
		}
	}
	return out, nil
}

func (b *Backend) UpdateFlags(ctx context.Context, ref storage.MessageRef, flags []string) error {
	result := b.db.WithContext(ctx).Model(&messageRow{}).
		Where("id = ? AND vhost = ? AND mailbox = ?", ref.Key, ref.Vhost, ref.Mailbox).
		Update("flags", encodeFlags(flags))
	if result.Error != nil {
		return fmt.Errorf("postgres: update flags for %q: %w", ref.Key, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("postgres: message %q not found", ref.Key)
	}
	return nil
}

func (b *Backend) Delete(ctx context.Context, ref storage.MessageRef) error {
	result := b.db.WithContext(ctx).
		Where("id = ? AND vhost = ? AND mailbox = ?", ref.Key, ref.Vhost, ref.Mailbox).
		Delete(&messageRow{})
	if result.Error != nil {
		return fmt.Errorf("postgres: delete %q: %w", ref.Key, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("postgres: message %q not found", ref.Key)
	}
	return nil
}

func (b *Backend) find(ctx context.Context, ref storage.MessageRef) (messageRow, error) {
	var row messageRow
	err := b.db.WithContext(ctx).
		Where("id = ? AND vhost = ? AND mailbox = ?", ref.Key, ref.Vhost, ref.Mailbox).
		First(&row).Error
	if err != nil {
		return messageRow{}, fmt.Errorf("postgres: message %q not found: %w", ref.Key, err)
	}
	return row, nil
}

// createdAt safely dereferences sql.BaseEntity's *time.Time CreatedAt
// (nil only pre-BeforeCreate, never for a row already read back from the
// database).
func createdAt(r messageRow) time.Time {
	if r.CreatedAt == nil {
		return time.Time{}
	}
	return *r.CreatedAt
}

func encodeFlags(flags []string) string {
	return strings.Join(flags, ",")
}

func decodeFlags(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
