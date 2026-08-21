package directory

import (
	"fmt"

	"gorm.io/gorm"
)

// Migrate creates/updates the accounts, vhosts, mailboxes, and dkim_keys
// tables, then backfills account_id on any pre-existing vhost.
func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&accountRow{}, &vhostRow{}, &mailboxRow{}, &dkimKeyRow{}); err != nil {
		return err
	}
	return backfillLegacyAccounts(db)
}

// backfillLegacyAccounts gives every pre-existing vhost with no account_id
// its own freshly created, 1:1 "legacy" Account — there is no way to infer
// real business groupings from existing data. Idempotent: only touches rows
// where account_id IS NULL/empty, so re-running (this whole migration
// system re-runs on every process boot — see
// internal/storage/migrations.All's doc) is safe, and once no such rows
// remain the trailing ALTER (tightening the column to NOT NULL) is itself a
// no-op, not an error.
func backfillLegacyAccounts(db *gorm.DB) error {
	var rows []vhostRow
	if err := db.Where("account_id IS NULL OR account_id = ''").Find(&rows).Error; err != nil {
		return fmt.Errorf("directory: find vhosts needing legacy account backfill: %w", err)
	}

	for _, v := range rows {
		err := db.Transaction(func(tx *gorm.DB) error {
			acct := accountRow{Name: "Legacy: " + v.Domain}
			if err := tx.Create(&acct).Error; err != nil {
				return err
			}
			return tx.Model(&vhostRow{}).Where("id = ?", v.Id).Update("account_id", acct.Id).Error
		})
		if err != nil {
			return fmt.Errorf("directory: backfill legacy account for vhost %q: %w", v.Domain, err)
		}
	}

	if err := db.Exec("ALTER TABLE vhosts ALTER COLUMN account_id SET NOT NULL").Error; err != nil {
		return fmt.Errorf("directory: tighten vhosts.account_id to NOT NULL: %w", err)
	}
	return nil
}
