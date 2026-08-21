package directory

import (
	"github.com/awesome-goose/goose/modules/sql"
)

// accountRow is the accounts table: a business/tenant that owns one or
// more vhosts (1 account : N vhosts) — the unit API tokens are scoped to
// (see internal/apiauth).
type accountRow struct {
	sql.BaseEntity

	Name string `gorm:"not null"`
}

func (accountRow) TableName() string { return "accounts" }

// vhostRow is the vhosts table (TRD §7). Embeds sql.BaseEntity for
// Id/CreatedAt/UpdatedAt/DeletedAt.
type vhostRow struct {
	sql.BaseEntity

	// AccountID is deliberately NOT `not null` at the struct-tag/AutoMigrate
	// level: GORM issues `ALTER TABLE vhosts ADD COLUMN account_id text NOT
	// NULL` verbatim from this tag, which fails outright against a
	// populated table with no default. The column is added nullable here,
	// backfilled by backfillLegacyAccounts, then tightened to NOT NULL via
	// an explicit ALTER once every row has a value — see migrate.go.
	AccountID string `gorm:"column:account_id;index"`

	Domain string `gorm:"uniqueIndex;not null"`
	Active bool   `gorm:"not null;default:true"`

	// FR-1.2 per-vhost policy.
	MaxMessageBytes         int64
	DailyQuota              int
	SpamRejectThreshold     float64
	SpamQuarantineThreshold float64
	// RetentionDays is NFR-COMP-1's per-vhost retention window. <= 0 means
	// unconfigured — internal/retention.Purger applies its own default
	// rather than this vhost never being purged, the same "0 means
	// unconfigured, a default applies at the enforcement site" convention
	// every other FR-1.2 field above already uses.
	RetentionDays int
}

func (vhostRow) TableName() string { return "vhosts" }

// mailboxRow is the mailboxes table (TRD §7).
type mailboxRow struct {
	sql.BaseEntity

	VhostID      string `gorm:"column:vhost_id;not null;uniqueIndex:idx_mailbox_vhost_local"`
	LocalPart    string `gorm:"not null;uniqueIndex:idx_mailbox_vhost_local"`
	PasswordHash string `gorm:"not null"`
}

func (mailboxRow) TableName() string { return "mailboxes" }

// dkimKeyRow is the dkim_keys table (TRD §7). Multiple rows per vhost
// support key rotation: at most one should have Active true at a time,
// enforced by Service.CreateVhost/RotateDKIMKey rather than a DB
// constraint (GORM has no native "at most one true" partial-unique-index
// helper, and the added complexity of a raw partial index isn't justified
// while every vhost has exactly one key — Phase 3 doesn't yet expose
// rotation via the API).
type dkimKeyRow struct {
	sql.BaseEntity

	VhostID  string `gorm:"column:vhost_id;not null;index"`
	Selector string `gorm:"not null"`
	// PrivateKeyPEM is unencrypted at rest. TRD R1 (DKIM/webhook-secret
	// encryption at rest) is an open risk explicitly deferred to Phase 6
	// ("resolve TRD R1... as a decision in this phase, not before") —
	// tracked there, not silently worked around here.
	PrivateKeyPEM string `gorm:"not null;type:text"`
	Active        bool   `gorm:"not null;default:true"`
}

func (dkimKeyRow) TableName() string { return "dkim_keys" }
