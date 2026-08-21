package apiauth

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/awesome-goose/goose/modules/sql"
	"gorm.io/gorm"
)

// tokenRow is the api_tokens table.
type tokenRow struct {
	sql.BaseEntity

	// AccountID is deliberately NOT `not null` at the struct-tag/AutoMigrate
	// level for the same reason vhostRow.AccountID isn't
	// (internal/directory/entities.go's doc): the column is added nullable
	// here, backfilled from the still-present vhost_id column by
	// backfillTokenAccountIDs, then tightened to NOT NULL via an explicit
	// ALTER once every row has a value.
	AccountID string `gorm:"column:account_id;index"` // "" for admin tokens

	// VhostID is the pre-account-scoping column, left mapped (not dropped)
	// so backfillTokenAccountIDs can join through it — see that function's
	// doc. No longer read by any Go code beyond the migration itself.
	VhostID   string `gorm:"column:vhost_id;index"`
	Label     string
	TokenHash string `gorm:"column:token_hash;uniqueIndex;not null"`
}

func (tokenRow) TableName() string { return "api_tokens" }

// MigratePostgres creates/updates the api_tokens table, then backfills
// account_id on any pre-existing token.
func MigratePostgres(db *gorm.DB) error {
	if err := db.AutoMigrate(&tokenRow{}); err != nil {
		return err
	}
	return backfillTokenAccountIDs(db)
}

// backfillTokenAccountIDs derives each pre-existing token's account_id from
// its (still-present) vhost_id, via the vhost's own now-backfilled
// account_id — safe because internal/directory.Migrate runs before this
// step in internal/storage/migrations.All's existing order, and because
// every persisted api_tokens row already has a real, non-empty vhost_id
// (TokenController.CreateToken always wrote one from a :vhostId URL param;
// the admin bootstrap credential is never a row in this table at all). A
// raw UPDATE, not a Go loop: idempotent (already-backfilled rows no longer
// match the WHERE clause) and simpler than directory's per-row loop, since
// no new row needs creating here, only a value copied across a join.
func backfillTokenAccountIDs(db *gorm.DB) error {
	err := db.Exec(`
		UPDATE api_tokens SET account_id = vhosts.account_id
		FROM vhosts
		WHERE vhosts.id = api_tokens.vhost_id
		  AND (api_tokens.account_id IS NULL OR api_tokens.account_id = '')
	`).Error
	if err != nil {
		return fmt.Errorf("apiauth: backfill token account_id: %w", err)
	}
	if err := db.Exec("ALTER TABLE api_tokens ALTER COLUMN account_id SET NOT NULL").Error; err != nil {
		return fmt.Errorf("apiauth: tighten api_tokens.account_id to NOT NULL: %w", err)
	}
	return nil
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

func (p *PostgresStore) CreateToken(ctx context.Context, id, accountID, label, tokenHash string) (Token, error) {
	if id == "" {
		return Token{}, fmt.Errorf("apiauth: token ID is required")
	}
	row := tokenRow{
		BaseEntity: sql.BaseEntity{UUIDAware: sql.UUIDAware{Id: id}},
		AccountID:  accountID, Label: label, TokenHash: tokenHash,
	}
	if err := p.db.WithContext(ctx).Create(&row).Error; err != nil {
		return Token{}, fmt.Errorf("apiauth: create token: %w", err)
	}
	return tokenFromRow(row), nil
}

func (p *PostgresStore) Authenticate(ctx context.Context, tokenHash string) (Token, bool, error) {
	var row tokenRow
	err := p.db.WithContext(ctx).First(&row, "token_hash = ?", tokenHash).Error
	if err != nil {
		if stderrors.Is(err, gorm.ErrRecordNotFound) {
			return Token{}, false, nil
		}
		return Token{}, false, fmt.Errorf("apiauth: authenticate: %w", err)
	}
	return tokenFromRow(row), true, nil
}

func (p *PostgresStore) ListTokens(ctx context.Context, accountID string) ([]Token, error) {
	var rows []tokenRow
	if err := p.db.WithContext(ctx).Where("account_id = ?", accountID).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("apiauth: list tokens for account %q: %w", accountID, err)
	}
	out := make([]Token, len(rows))
	for i, r := range rows {
		out[i] = tokenFromRow(r)
	}
	return out, nil
}

func (p *PostgresStore) ListTokensPage(ctx context.Context, accountID, cursor string, limit int) ([]Token, error) {
	if limit <= 0 {
		limit = DefaultPageSize
	}
	if limit > MaxPageSize {
		limit = MaxPageSize
	}

	q := p.db.WithContext(ctx).Where("account_id = ?", accountID).Order("id ASC").Limit(limit)
	if cursor != "" {
		q = q.Where("id > ?", cursor)
	}

	var rows []tokenRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("apiauth: list tokens for account %q: %w", accountID, err)
	}
	out := make([]Token, len(rows))
	for i, r := range rows {
		out[i] = tokenFromRow(r)
	}
	return out, nil
}

func (p *PostgresStore) RevokeToken(ctx context.Context, accountID, id string) error {
	result := p.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, id).Delete(&tokenRow{})
	if result.Error != nil {
		return fmt.Errorf("apiauth: revoke token %q: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("apiauth: token %q: %w", id, ErrNotFound)
	}
	return nil
}

func tokenFromRow(r tokenRow) Token {
	tok := Token{ID: r.Id, AccountID: r.AccountID, Label: r.Label}
	if r.CreatedAt != nil {
		tok.CreatedAt = *r.CreatedAt
	}
	return tok
}
