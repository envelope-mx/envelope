package audit

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/awesome-goose/goose/modules/sql"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// entryRow is the audit_log table (TRD §7).
type entryRow struct {
	sql.BaseEntity

	Actor  string `gorm:"not null"`
	Action string `gorm:"not null"`
	Target string `gorm:"index"`
	Detail string
	At     time.Time `gorm:"not null;index"`
}

func (entryRow) TableName() string { return "audit_log" }

// MigratePostgres creates/updates the audit_log table.
func MigratePostgres(db *gorm.DB) error {
	return db.AutoMigrate(&entryRow{})
}

// PostgresStore is the durable Store implementation.
type PostgresStore struct {
	db *gorm.DB
}

// NewPostgresStore returns a Store backed by db. Callers must run
// MigratePostgres (or internal/storage/migrations.All) first.
func NewPostgresStore(db *gorm.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

var _ Store = (*PostgresStore)(nil)

func (p *PostgresStore) Record(ctx context.Context, entry Entry) error {
	if entry.At.IsZero() {
		entry.At = time.Now()
	}
	row := entryRow{
		BaseEntity: sql.BaseEntity{UUIDAware: sql.UUIDAware{Id: uuid.NewString()}},
		Actor:      entry.Actor, Action: entry.Action, Target: entry.Target, Detail: entry.Detail, At: entry.At,
	}
	if err := p.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("audit: record entry: %w", err)
	}
	return nil
}

func (p *PostgresStore) List(ctx context.Context, target string) ([]Entry, error) {
	var rows []entryRow
	if err := p.db.WithContext(ctx).Where("target = ?", target).Order("at DESC, id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("audit: list entries for target %q: %w", target, err)
	}
	out := make([]Entry, len(rows))
	for i, r := range rows {
		out[i] = entryFromRow(r)
	}
	return out, nil
}

// ListPage's cursor resolves the previous page's last entry's own (at, id)
// first, then filters strictly older than that pair — a plain "at < ?"
// filter alone would incorrectly skip or repeat rows whenever two entries
// share the same `at` value (plausible: audit entries are written at
// ordinary request latency, so two fast successive admin actions can land
// within the same timestamp's resolution), which is exactly the class of
// pagination bug ListVhosts's own fix (directory.Service.ListVhosts's doc)
// was about — id DESC as the tiebreaker makes the (at, id) pair unique and
// stable to page over even when `at` alone isn't.
func (p *PostgresStore) ListPage(ctx context.Context, target, cursor string, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = DefaultPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}

	q := p.db.WithContext(ctx).Where("target = ?", target).Order("at DESC, id DESC").Limit(limit)
	if cursor != "" {
		var after entryRow
		err := p.db.WithContext(ctx).Select("at", "id").First(&after, "id = ?", cursor).Error
		if err != nil {
			if stderrors.Is(err, gorm.ErrRecordNotFound) {
				return nil, nil // an unknown/stale cursor yields an empty page, not an error
			}
			return nil, fmt.Errorf("audit: resolve cursor %q: %w", cursor, err)
		}
		q = q.Where("at < ? OR (at = ? AND id < ?)", after.At, after.At, after.Id)
	}

	var rows []entryRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("audit: list entries for target %q: %w", target, err)
	}
	out := make([]Entry, len(rows))
	for i, r := range rows {
		out[i] = entryFromRow(r)
	}
	return out, nil
}

func entryFromRow(r entryRow) Entry {
	return Entry{ID: r.Id, Actor: r.Actor, Action: r.Action, Target: r.Target, Detail: r.Detail, At: r.At}
}
