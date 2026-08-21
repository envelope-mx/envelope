package directory

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	stderrors "errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/isaiahiroko/envelope/internal/kms"
)

// Service is the Postgres-backed Directory implementation (TRD FR-1.x).
// See the package doc for why it's built on *gorm.DB directly rather than
// Goose's sql.Entity[T]/Query helpers.
type Service struct {
	db  *gorm.DB
	enc kms.Encryptor
}

// New returns a Service backed by db, encrypting DKIM private keys at
// rest via enc (TRD R1, NFR-SEC-3 — see internal/kms's package doc). enc
// must not be nil in production; tests use a real kms.AESGCMEncryptor
// with a fixed test key rather than a no-op stand-in, so the encrypt/
// decrypt round trip is exercised for real. Callers must run
// Migrate(ctx, db) (internal/storage/migrations) before using it against a
// fresh database.
func New(db *gorm.DB, enc kms.Encryptor) *Service {
	return &Service{db: db, enc: enc}
}

var _ Directory = (*Service)(nil)

// CreateVhost registers domain as an active vhost under accountID with a
// freshly generated DKIM key pair under DefaultDKIMSelector (FR-1.1,
// FR-1.2: adding a domain is a data operation, never a config edit or
// restart). accountID is not verified to exist here — the same convention
// CreateMailbox already uses for vhostID: verifying the parent resource
// exists is the calling controller's job (it needs to 404 before this call
// anyway to avoid orphaning a vhost row under a bogus account).
func (s *Service) CreateVhost(ctx context.Context, accountID, domain string) (Vhost, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Vhost{}, fmt.Errorf("directory: generate DKIM key for %q: %w", domain, err)
	}
	keyPEM, err := encodeRSAKeyPEM(key)
	if err != nil {
		return Vhost{}, fmt.Errorf("directory: encode DKIM key for %q: %w", domain, err)
	}
	encryptedPEM, err := s.encryptPEM(keyPEM)
	if err != nil {
		return Vhost{}, fmt.Errorf("directory: encrypt DKIM key for %q: %w", domain, err)
	}

	row := vhostRow{AccountID: accountID, Domain: domain, Active: true}
	var dkimRow dkimKeyRow

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		dkimRow = dkimKeyRow{
			VhostID:       row.Id,
			Selector:      DefaultDKIMSelector,
			PrivateKeyPEM: encryptedPEM,
			Active:        true,
		}
		return tx.Create(&dkimRow).Error
	})
	if err != nil {
		return Vhost{}, fmt.Errorf("directory: create vhost %q: %w", domain, err)
	}

	return Vhost{
		ID: row.Id, AccountID: row.AccountID, Domain: row.Domain, Active: row.Active,
		DKIMSelector: dkimRow.Selector, DKIMKey: key,
	}, nil
}

// CreateAccount registers a new business/tenant. Every subsequent vhost
// created under it (self-serve, via CreateVhost) and every API token
// scoped to it (internal/apiauth) references this ID.
func (s *Service) CreateAccount(ctx context.Context, name string) (Account, error) {
	row := accountRow{Name: name}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return Account{}, fmt.Errorf("directory: create account %q: %w", name, err)
	}
	return accountFromRow(row), nil
}

// GetAccount returns the account with the given ID.
func (s *Service) GetAccount(ctx context.Context, id string) (Account, error) {
	var row accountRow
	if err := s.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		if stderrors.Is(err, gorm.ErrRecordNotFound) {
			return Account{}, fmt.Errorf("directory: account %q: %w", id, ErrNotFound)
		}
		return Account{}, fmt.Errorf("directory: get account %q: %w", id, err)
	}
	return accountFromRow(row), nil
}

// ListAccounts returns up to limit accounts (admin/API surface — account
// management is platform-level), cursor-paginated the same way ListVhosts
// is — see that method's doc for why.
func (s *Service) ListAccounts(ctx context.Context, cursor string, limit int) ([]Account, error) {
	if limit <= 0 {
		limit = DefaultVhostPageSize
	}
	if limit > MaxVhostPageSize {
		limit = MaxVhostPageSize
	}

	q := s.db.WithContext(ctx).Order("id ASC").Limit(limit)
	if cursor != "" {
		q = q.Where("id > ?", cursor)
	}

	var rows []accountRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("directory: list accounts: %w", err)
	}

	out := make([]Account, len(rows))
	for i, r := range rows {
		out[i] = accountFromRow(r)
	}
	return out, nil
}

func accountFromRow(row accountRow) Account {
	a := Account{ID: row.Id, Name: row.Name}
	if row.CreatedAt != nil {
		a.CreatedAt = *row.CreatedAt
	}
	return a
}

// DefaultVhostPageSize/MaxVhostPageSize bound ListVhosts and
// ListMailboxesPage (FR-5.4: list endpoints are paginated, no unbounded
// result sets — a gap ListVhosts specifically had until a real 100k-row
// timing test, TestScaleTo100kVhosts, TRD §6.1, measured it returning the
// full, unpaginated table in ~11s). The other list endpoints in this
// codebase (webhook subscriptions, tokens, delivery attempts, audit
// entries) have the same cursor-paginated sibling-method pattern applied
// in their own packages (webhook.Store.ListSubscriptionsPage/
// ListAttemptsPage, apiauth.Store.ListTokensPage, audit.Store.ListPage).
const (
	DefaultVhostPageSize = 100
	MaxVhostPageSize     = 500
)

// ListVhosts returns up to limit vhosts (admin/API surface — vhost
// management is platform-level, not itself vhost-scoped), ordered by id
// for stable, gap-free cursor pagination: cursor is the last ID seen on
// the previous page ("" for the first page). limit <= 0 defaults to
// DefaultVhostPageSize; values above MaxVhostPageSize are capped there.
func (s *Service) ListVhosts(ctx context.Context, cursor string, limit int) ([]Vhost, error) {
	if limit <= 0 {
		limit = DefaultVhostPageSize
	}
	if limit > MaxVhostPageSize {
		limit = MaxVhostPageSize
	}

	q := s.db.WithContext(ctx).Order("id ASC").Limit(limit)
	if cursor != "" {
		q = q.Where("id > ?", cursor)
	}

	var rows []vhostRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("directory: list vhosts: %w", err)
	}

	out := make([]Vhost, len(rows))
	for i, r := range rows {
		out[i] = vhostFromRow(r, nil)
	}
	return out, nil
}

// GetVhost returns the vhost with the given ID, including its active DKIM
// key.
func (s *Service) GetVhost(ctx context.Context, id string) (Vhost, error) {
	var row vhostRow
	if err := s.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		if stderrors.Is(err, gorm.ErrRecordNotFound) {
			return Vhost{}, fmt.Errorf("directory: vhost %q: %w", id, ErrNotFound)
		}
		return Vhost{}, fmt.Errorf("directory: get vhost %q: %w", id, err)
	}
	return s.hydrateVhost(ctx, row)
}

// Vhost returns domain's Vhost, if registered (Directory interface).
func (s *Service) Vhost(ctx context.Context, domain string) (Vhost, bool) {
	var row vhostRow
	if err := s.db.WithContext(ctx).First(&row, "domain = ?", domain).Error; err != nil {
		return Vhost{}, false
	}
	v, err := s.hydrateVhost(ctx, row)
	if err != nil {
		return Vhost{}, false
	}
	return v, true
}

// VhostActive reports whether domain is a registered, active vhost
// (Directory interface; FR-2.2).
func (s *Service) VhostActive(ctx context.Context, domain string) bool {
	v, ok := s.Vhost(ctx, domain)
	return ok && v.Active
}

// DeactivateVhost stops a vhost from accepting inbound mail or new
// submission (FR-1.4). The change is visible immediately: FR-2.2's inbound
// check and submission's auth check both query the Directory live on
// every connection, so there's no separate propagation delay to account
// for beyond ordinary query latency — well under FR-1.4's 60-second bound.
func (s *Service) DeactivateVhost(ctx context.Context, id string) error {
	result := s.db.WithContext(ctx).Model(&vhostRow{}).Where("id = ?", id).Update("active", false)
	if result.Error != nil {
		return fmt.Errorf("directory: deactivate vhost %q: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("directory: vhost %q: %w", id, ErrNotFound)
	}
	return nil
}

func (s *Service) hydrateVhost(ctx context.Context, row vhostRow) (Vhost, error) {
	var dkimRow dkimKeyRow
	err := s.db.WithContext(ctx).
		Where("vhost_id = ? AND active = ?", row.Id, true).
		Order("created_at DESC").
		First(&dkimRow).Error
	if err != nil && !stderrors.Is(err, gorm.ErrRecordNotFound) {
		return Vhost{}, fmt.Errorf("directory: load DKIM key for vhost %q: %w", row.Domain, err)
	}

	var key *rsa.PrivateKey
	if dkimRow.Id != "" {
		keyPEM, err := s.decryptPEM(dkimRow.PrivateKeyPEM)
		if err != nil {
			return Vhost{}, fmt.Errorf("directory: decrypt DKIM key for vhost %q: %w", row.Domain, err)
		}
		key, err = decodeRSAKeyPEM(keyPEM)
		if err != nil {
			return Vhost{}, fmt.Errorf("directory: decode DKIM key for vhost %q: %w", row.Domain, err)
		}
	}

	return vhostFromRow(row, key), nil
}

// encryptPEM/decryptPEM apply TRD R1's at-rest encryption (internal/kms)
// to a PEM-encoded key before it's written to/after it's read from
// dkim_keys.private_key_pem. The column stays a text column (base64 of
// the AES-GCM ciphertext) rather than switching to bytea, so this is a
// value-encoding change only, not a schema migration.
func (s *Service) encryptPEM(keyPEM string) (string, error) {
	ciphertext, err := s.enc.Encrypt([]byte(keyPEM))
	if err != nil {
		return "", fmt.Errorf("directory: encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *Service) decryptPEM(stored string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return "", fmt.Errorf("directory: decode stored ciphertext: %w", err)
	}
	plaintext, err := s.enc.Decrypt(ciphertext)
	if err != nil {
		return "", fmt.Errorf("directory: decrypt: %w", err)
	}
	return string(plaintext), nil
}

func vhostFromRow(row vhostRow, key *rsa.PrivateKey) Vhost {
	v := Vhost{
		ID: row.Id, AccountID: row.AccountID, Domain: row.Domain, Active: row.Active,
		DKIMSelector: DefaultDKIMSelector, DKIMKey: key,
		MaxMessageBytes:         row.MaxMessageBytes,
		DailyQuota:              row.DailyQuota,
		SpamRejectThreshold:     row.SpamRejectThreshold,
		SpamQuarantineThreshold: row.SpamQuarantineThreshold,
		RetentionDays:           row.RetentionDays,
	}
	return v
}

// UpdateVhostPolicy sets id's FR-1.2/NFR-COMP-1 policy fields wholesale
// (every field in policy is written; there is no partial-update variant —
// a caller wanting to change one field must first read the vhost's current
// policy via GetVhost and send the full set back). This is also the first
// write path any of these fields have ever had via Service: they've been
// modeled and returned since Phase 3 but only ever set implicitly to their
// zero value at CreateVhost, with no way to configure them afterward —
// closed here because NFR-COMP-1 specifically requires retention be
// "configurable per vhost," which a model-only field isn't.
func (s *Service) UpdateVhostPolicy(ctx context.Context, id string, policy VhostPolicy) error {
	result := s.db.WithContext(ctx).Model(&vhostRow{}).Where("id = ?", id).Updates(map[string]any{
		"max_message_bytes":         policy.MaxMessageBytes,
		"daily_quota":               policy.DailyQuota,
		"spam_reject_threshold":     policy.SpamRejectThreshold,
		"spam_quarantine_threshold": policy.SpamQuarantineThreshold,
		"retention_days":            policy.RetentionDays,
	})
	if result.Error != nil {
		return fmt.Errorf("directory: update vhost policy %q: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("directory: vhost %q: %w", id, ErrNotFound)
	}
	return nil
}

// RotateDKIMKeys re-encrypts every stored DKIM private key from oldEnc to
// newEnc — the DKIM half of docs/RUNBOOK.md §4.7's "no rotation tool" gap,
// closed (the webhook-secret half is webhook.PostgresStore.RotateSecrets).
// Must run with no live app process reading/writing dkim_keys under the old
// key concurrently — a concurrent decrypt under the old key for a row this
// method has already rewritten under the new one would fail. Resumable: a
// row that fails to decrypt under oldEnc but succeeds under newEnc is
// treated as already rotated by a prior, interrupted run and skipped
// rather than re-rotated or treated as an error, so re-running after a
// partial failure is safe. See cmd/envelope/main.go's --rotate-master-key.
func (s *Service) RotateDKIMKeys(ctx context.Context, oldEnc, newEnc kms.Encryptor) (rotated int, err error) {
	var rows []dkimKeyRow
	if err := s.db.WithContext(ctx).Find(&rows).Error; err != nil {
		return 0, fmt.Errorf("directory: list dkim keys for rotation: %w", err)
	}

	for _, row := range rows {
		ciphertext, err := base64.StdEncoding.DecodeString(row.PrivateKeyPEM)
		if err != nil {
			return rotated, fmt.Errorf("directory: decode stored ciphertext for dkim key %q: %w", row.Id, err)
		}

		plaintext, err := oldEnc.Decrypt(ciphertext)
		if err != nil {
			if _, err2 := newEnc.Decrypt(ciphertext); err2 == nil {
				continue // already rotated by a prior, interrupted run
			}
			return rotated, fmt.Errorf("directory: decrypt dkim key %q under old key: %w", row.Id, err)
		}

		newCiphertext, err := newEnc.Encrypt(plaintext)
		if err != nil {
			return rotated, fmt.Errorf("directory: re-encrypt dkim key %q under new key: %w", row.Id, err)
		}
		encoded := base64.StdEncoding.EncodeToString(newCiphertext)
		if err := s.db.WithContext(ctx).Model(&dkimKeyRow{}).Where("id = ?", row.Id).
			Update("private_key_pem", encoded).Error; err != nil {
			return rotated, fmt.Errorf("directory: write rotated dkim key %q: %w", row.Id, err)
		}
		rotated++
	}
	return rotated, nil
}

// CreateMailbox registers a mailbox credential under vhostID, which must
// already be registered via CreateVhost. The password is bcrypt-hashed
// before storage (NFR-SEC-2) — unlike Phase 2's throwaway in-memory
// Directory, this is a real, persisted credential store.
func (s *Service) CreateMailbox(ctx context.Context, vhostID, localPart, password string) (Mailbox, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return Mailbox{}, fmt.Errorf("directory: hash password: %w", err)
	}

	row := mailboxRow{VhostID: vhostID, LocalPart: localPart, PasswordHash: string(hash)}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return Mailbox{}, fmt.Errorf("directory: create mailbox %q: %w", localPart, err)
	}
	return Mailbox{ID: row.Id, VhostID: row.VhostID, LocalPart: row.LocalPart, PasswordHash: row.PasswordHash}, nil
}

// ListMailboxes returns every one of vhostID's mailboxes, unbounded
// (FR-1.5: vhostID is a mandatory parameter baked into the query below, not
// an optional filter — there is no code path in this method that can
// return another vhost's rows). Kept deliberately unbounded rather than
// switched to ListMailboxesPage's cursor pagination: DataController.Export
// needs every mailbox for a complete GDPR export (NFR-COMP-2), where
// silently truncating to one page would make the export lie about being
// complete.
func (s *Service) ListMailboxes(ctx context.Context, vhostID string) ([]Mailbox, error) {
	var rows []mailboxRow
	if err := s.db.WithContext(ctx).Where("vhost_id = ?", vhostID).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("directory: list mailboxes for vhost %q: %w", vhostID, err)
	}
	out := make([]Mailbox, len(rows))
	for i, r := range rows {
		out[i] = Mailbox{ID: r.Id, VhostID: r.VhostID, LocalPart: r.LocalPart, PasswordHash: r.PasswordHash}
	}
	return out, nil
}

// ListMailboxesPage returns up to limit of vhostID's mailboxes (FR-5.4),
// cursor-paginated the same way ListVhosts is — see that method's doc for
// why this endpoint specifically needed it, and ListMailboxes's doc for why
// that method stays unbounded instead of being replaced by this one.
// VhostController.ListMailboxes (the API handler) calls this; internal
// callers needing every mailbox call ListMailboxes.
func (s *Service) ListMailboxesPage(ctx context.Context, vhostID, cursor string, limit int) ([]Mailbox, error) {
	if limit <= 0 {
		limit = DefaultVhostPageSize
	}
	if limit > MaxVhostPageSize {
		limit = MaxVhostPageSize
	}

	q := s.db.WithContext(ctx).Where("vhost_id = ?", vhostID).Order("id ASC").Limit(limit)
	if cursor != "" {
		q = q.Where("id > ?", cursor)
	}

	var rows []mailboxRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("directory: list mailboxes for vhost %q: %w", vhostID, err)
	}
	out := make([]Mailbox, len(rows))
	for i, r := range rows {
		out[i] = Mailbox{ID: r.Id, VhostID: r.VhostID, LocalPart: r.LocalPart, PasswordHash: r.PasswordHash}
	}
	return out, nil
}

// GetMailbox returns mailboxID within vhostID (FR-1.5: both the vhost and
// mailbox ID are required — a mailbox ID from a different vhost matches
// nothing, by construction of the WHERE clause, not by an application-level
// ownership check bolted on afterward).
func (s *Service) GetMailbox(ctx context.Context, vhostID, mailboxID string) (Mailbox, error) {
	var row mailboxRow
	err := s.db.WithContext(ctx).Where("vhost_id = ? AND id = ?", vhostID, mailboxID).First(&row).Error
	if err != nil {
		if stderrors.Is(err, gorm.ErrRecordNotFound) {
			return Mailbox{}, fmt.Errorf("directory: mailbox %q in vhost %q: %w", mailboxID, vhostID, ErrNotFound)
		}
		return Mailbox{}, fmt.Errorf("directory: get mailbox %q: %w", mailboxID, err)
	}
	return Mailbox{ID: row.Id, VhostID: row.VhostID, LocalPart: row.LocalPart, PasswordHash: row.PasswordHash}, nil
}

// DeleteMailbox removes mailboxID within vhostID (FR-1.5: see GetMailbox).
func (s *Service) DeleteMailbox(ctx context.Context, vhostID, mailboxID string) error {
	result := s.db.WithContext(ctx).Where("vhost_id = ? AND id = ?", vhostID, mailboxID).Delete(&mailboxRow{})
	if result.Error != nil {
		return fmt.Errorf("directory: delete mailbox %q: %w", mailboxID, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("directory: mailbox %q in vhost %q: %w", mailboxID, vhostID, ErrNotFound)
	}
	return nil
}

// Authenticate reports whether password matches localPart@vhost's stored
// credential (Directory interface; FR-3.1, FR-7.2).
func (s *Service) Authenticate(ctx context.Context, vhost, localPart, password string) bool {
	var vhostRow vhostRow
	if err := s.db.WithContext(ctx).Select("id").First(&vhostRow, "domain = ?", vhost).Error; err != nil {
		return false
	}

	var row mailboxRow
	err := s.db.WithContext(ctx).
		Where("vhost_id = ? AND local_part = ?", vhostRow.Id, localPart).
		First(&row).Error
	if err != nil {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(row.PasswordHash), []byte(password)) == nil
}

func encodeRSAKeyPEM(key *rsa.PrivateKey) (string, error) {
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func decodeRSAKeyPEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("directory: no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
