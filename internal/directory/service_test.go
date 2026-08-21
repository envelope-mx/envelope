package directory_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/dbtest"
	"github.com/isaiahiroko/envelope/internal/directory"
	"github.com/isaiahiroko/envelope/internal/kms"
)

// testEncryptor is a real AES-256-GCM encryptor (not a no-op stand-in)
// under a fixed test key, so these tests exercise the actual TRD R1
// encrypt/decrypt round trip against Postgres, not just a happy-path
// stub.
func testEncryptor(t *testing.T) kms.Encryptor {
	t.Helper()
	enc, err := kms.NewAESGCMEncryptor(bytes.Repeat([]byte("k"), kms.KeySize))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	return enc
}

// newService intentionally does not truncate vhosts/mailboxes/dkim_keys:
// those tables are shared with internal/api's tests against the same
// database, and `go test ./...` runs different packages' test binaries
// concurrently — a TRUNCATE here can wipe rows another package's test just
// created. Every test in this file scopes its assertions to a domain/ID it
// just created (see uniqueDomain), so isolation comes from uniqueness, not
// a clean table.
func newService(t *testing.T) *directory.Service {
	t.Helper()
	db := dbtest.DB(t)
	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return directory.New(db, testEncryptor(t))
}

// uniqueDomain avoids collisions both across packages sharing this
// database concurrently and across repeated runs against it (nothing here
// truncates between invocations, so a plain t.Name()-based domain would
// collide with the previous run's leftover row).
func uniqueDomain(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%s.test", t.Name(), uuid.NewString())
}

// mustCreateAccount creates a fresh account for a test to create vhosts
// under — every CreateVhost call now needs an owning account (1 Account :
// N Vhosts), mirroring uniqueDomain's role for domains.
func mustCreateAccount(t *testing.T, s *directory.Service) directory.Account {
	t.Helper()
	acct, err := s.CreateAccount(context.Background(), t.Name()+"-"+uuid.NewString())
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	return acct
}

func TestServiceCreateVhostAndLookup(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	acct := mustCreateAccount(t, s)
	domain := uniqueDomain(t)

	created, err := s.CreateVhost(ctx, acct.ID, domain)
	if err != nil {
		t.Fatalf("CreateVhost: %v", err)
	}
	if created.ID == "" || created.AccountID != acct.ID || created.DKIMKey == nil || !created.Active {
		t.Fatalf("unexpected vhost: %+v", created)
	}

	got, ok := s.Vhost(ctx, domain)
	if !ok {
		t.Fatal("expected Vhost to find the created vhost")
	}
	if got.ID != created.ID || got.DKIMKey == nil {
		t.Fatalf("Vhost() = %+v, want ID %q with a DKIM key", got, created.ID)
	}
	if !s.VhostActive(ctx, domain) {
		t.Fatal("expected newly created vhost to be active")
	}

	byID, err := s.GetVhost(ctx, created.ID)
	if err != nil || byID.Domain != domain {
		t.Fatalf("GetVhost: %+v, %v", byID, err)
	}
}

func TestServiceListVhosts(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	acct := mustCreateAccount(t, s)

	domainA, domainB := uniqueDomain(t)+"-a", uniqueDomain(t)+"-b"
	if _, err := s.CreateVhost(ctx, acct.ID, domainA); err != nil {
		t.Fatalf("CreateVhost a: %v", err)
	}
	if _, err := s.CreateVhost(ctx, acct.ID, domainB); err != nil {
		t.Fatalf("CreateVhost b: %v", err)
	}

	// Asserting an exact list length here would be racy: the vhosts table
	// is intentionally left untruncated between tests (see newService's
	// doc) since go test runs packages concurrently and several other
	// packages create vhosts of their own against the same database. So
	// this only checks that the two vhosts just created are present, not
	// that they're the only ones — paginating through every page (a small
	// fixed limit, deliberately, so this also exercises cursor advancement
	// rather than fetching everything in one large page) rather than
	// asserting against a single unbounded/large-limit call, which would
	// itself be racy against however large the shared table has grown.
	var got []directory.Vhost
	cursor := ""
	for {
		page, err := s.ListVhosts(ctx, cursor, 25)
		if err != nil {
			t.Fatalf("ListVhosts: %v", err)
		}
		got = append(got, page...)
		if len(page) < 25 {
			break
		}
		cursor = page[len(page)-1].ID
	}
	foundA, foundB := false, false
	for _, v := range got {
		switch v.Domain {
		case domainA:
			foundA = true
		case domainB:
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Fatalf("expected both created vhosts in the list: foundA=%v foundB=%v", foundA, foundB)
	}
}

func TestServiceDeactivateVhost(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	acct := mustCreateAccount(t, s)
	domain := uniqueDomain(t)

	v, err := s.CreateVhost(ctx, acct.ID, domain)
	if err != nil {
		t.Fatalf("CreateVhost: %v", err)
	}

	if err := s.DeactivateVhost(ctx, v.ID); err != nil {
		t.Fatalf("DeactivateVhost: %v", err)
	}

	if s.VhostActive(ctx, domain) {
		t.Fatal("expected vhost to be inactive after DeactivateVhost")
	}
	got, ok := s.Vhost(ctx, domain)
	if !ok || got.Active {
		t.Fatalf("expected Vhost to report Active=false, got %+v (ok=%v)", got, ok)
	}
}

func TestServiceDeactivateUnknownVhost(t *testing.T) {
	s := newService(t)
	if err := s.DeactivateVhost(context.Background(), "does-not-exist"); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestUpdateVhostPolicy covers NFR-COMP-1: retention must actually be
// configurable per vhost, not just modeled and stuck at its zero value.
func TestUpdateVhostPolicy(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	acct := mustCreateAccount(t, s)
	domain := uniqueDomain(t)

	v, err := s.CreateVhost(ctx, acct.ID, domain)
	if err != nil {
		t.Fatalf("CreateVhost: %v", err)
	}
	if v.RetentionDays != 0 {
		t.Fatalf("expected RetentionDays 0 (unconfigured) right after creation, got %d", v.RetentionDays)
	}

	err = s.UpdateVhostPolicy(ctx, v.ID, directory.VhostPolicy{
		MaxMessageBytes:         1 << 20,
		DailyQuota:              500,
		SpamRejectThreshold:     8.5,
		SpamQuarantineThreshold: 5,
		RetentionDays:           30,
	})
	if err != nil {
		t.Fatalf("UpdateVhostPolicy: %v", err)
	}

	got, err := s.GetVhost(ctx, v.ID)
	if err != nil {
		t.Fatalf("GetVhost: %v", err)
	}
	if got.MaxMessageBytes != 1<<20 || got.DailyQuota != 500 || got.SpamRejectThreshold != 8.5 ||
		got.SpamQuarantineThreshold != 5 || got.RetentionDays != 30 {
		t.Fatalf("policy fields not persisted, got %+v", got)
	}
}

func TestUpdateVhostPolicyUnknownVhost(t *testing.T) {
	s := newService(t)
	err := s.UpdateVhostPolicy(context.Background(), "does-not-exist", directory.VhostPolicy{RetentionDays: 30})
	if !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestServiceMailboxCRUDAndAuthenticate(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	acct := mustCreateAccount(t, s)
	domain := uniqueDomain(t)

	v, err := s.CreateVhost(ctx, acct.ID, domain)
	if err != nil {
		t.Fatalf("CreateVhost: %v", err)
	}

	mb, err := s.CreateMailbox(ctx, v.ID, "alice", "s3cret")
	if err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}
	if mb.PasswordHash == "s3cret" {
		t.Fatal("expected password to be hashed, not stored in plaintext")
	}

	if !s.Authenticate(ctx, domain, "alice", "s3cret") {
		t.Fatal("expected correct credentials to authenticate")
	}
	if s.Authenticate(ctx, domain, "alice", "wrong") {
		t.Fatal("expected wrong password to fail")
	}

	list, err := s.ListMailboxes(ctx, v.ID)
	if err != nil || len(list) != 1 || list[0].ID != mb.ID {
		t.Fatalf("ListMailboxes: %+v, %v", list, err)
	}

	got, err := s.GetMailbox(ctx, v.ID, mb.ID)
	if err != nil || got.LocalPart != "alice" {
		t.Fatalf("GetMailbox: %+v, %v", got, err)
	}

	if err := s.DeleteMailbox(ctx, v.ID, mb.ID); err != nil {
		t.Fatalf("DeleteMailbox: %v", err)
	}
	if _, err := s.GetMailbox(ctx, v.ID, mb.ID); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestServiceMailboxIsolatedByVhost is the FR-1.5 test: a mailbox ID that
// is real, but belongs to a different vhost, must not be reachable through
// another vhost's ID. This exercises the actual query path (GetMailbox/
// DeleteMailbox), not just a code-review claim that the predicate is
// applied.
func TestServiceMailboxIsolatedByVhost(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	acct := mustCreateAccount(t, s)

	vA, err := s.CreateVhost(ctx, acct.ID, uniqueDomain(t)+"-a")
	if err != nil {
		t.Fatalf("CreateVhost A: %v", err)
	}
	vB, err := s.CreateVhost(ctx, acct.ID, uniqueDomain(t)+"-b")
	if err != nil {
		t.Fatalf("CreateVhost B: %v", err)
	}

	mbA, err := s.CreateMailbox(ctx, vA.ID, "alice", "s3cret")
	if err != nil {
		t.Fatalf("CreateMailbox A: %v", err)
	}

	// Querying A's mailbox through B's vhost ID must find nothing.
	if _, err := s.GetMailbox(ctx, vB.ID, mbA.ID); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-vhost GetMailbox, got %v", err)
	}

	listB, err := s.ListMailboxes(ctx, vB.ID)
	if err != nil {
		t.Fatalf("ListMailboxes B: %v", err)
	}
	for _, mb := range listB {
		if mb.ID == mbA.ID {
			t.Fatalf("vhost B's mailbox list leaked vhost A's mailbox: %+v", mb)
		}
	}

	// Deleting A's mailbox through B's vhost ID must fail, and the
	// mailbox must still exist afterward.
	if err := s.DeleteMailbox(ctx, vB.ID, mbA.ID); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-vhost DeleteMailbox, got %v", err)
	}
	if _, err := s.GetMailbox(ctx, vA.ID, mbA.ID); err != nil {
		t.Fatalf("expected mailbox A to survive the cross-vhost delete attempt, got %v", err)
	}
}

// TestListMailboxesPage exercises FR-5.4's cursor pagination for
// ListMailboxesPage the same way TestScaleTo100kVhosts's pagination sweep
// does for ListVhosts, just at a size that doesn't need the scale-test
// opt-in gate: every mailbox must appear exactly once across the full
// sweep, regardless of page boundaries.
func TestListMailboxesPage(t *testing.T) {
	ctx := context.Background()
	s := newService(t)
	acct := mustCreateAccount(t, s)
	v, err := s.CreateVhost(ctx, acct.ID, uniqueDomain(t))
	if err != nil {
		t.Fatalf("CreateVhost: %v", err)
	}

	const total = 5
	for i := 0; i < total; i++ {
		if _, err := s.CreateMailbox(ctx, v.ID, fmt.Sprintf("user%d", i), "s3cret"); err != nil {
			t.Fatalf("CreateMailbox %d: %v", i, err)
		}
	}

	seen := make(map[string]bool)
	cursor := ""
	for {
		page, err := s.ListMailboxesPage(ctx, v.ID, cursor, 2)
		if err != nil {
			t.Fatalf("ListMailboxesPage: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, mb := range page {
			if seen[mb.ID] {
				t.Fatalf("mailbox %q returned on more than one page", mb.ID)
			}
			seen[mb.ID] = true
		}
		if len(page) < 2 {
			break
		}
		cursor = page[len(page)-1].ID
	}

	if len(seen) != total {
		t.Fatalf("expected %d distinct mailboxes across all pages, got %d", total, len(seen))
	}
}

// TestRotateDKIMKeys is gated behind ENVELOPE_RUN_DESTRUCTIVE_TESTS (unlike
// every other test in this file) because RotateDKIMKeys rewrites existing
// rows in place across the whole vhosts/dkim_keys tables, not just adds new
// uniquely-keyed ones — the isolation-by-uniqueness convention the rest of
// this package relies on (see newService's doc) doesn't protect a
// concurrently running package's test data from an in-place rewrite the
// way it protects against inserts. Truncating first requires opting in
// explicitly and running this alone:
//
//	ENVELOPE_RUN_DESTRUCTIVE_TESTS=1 ENVELOPE_TEST_POSTGRES_DSN=... \
//	  go test ./internal/directory/... -run TestRotateDKIMKeys -v
func TestRotateDKIMKeys(t *testing.T) {
	if os.Getenv("ENVELOPE_RUN_DESTRUCTIVE_TESTS") == "" {
		t.Skip("ENVELOPE_RUN_DESTRUCTIVE_TESTS not set; skipping (see test doc to opt in)")
	}
	db := dbtest.DB(t)
	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	dbtest.Truncate(t, db, "dkim_keys", "vhosts")

	oldEnc := testEncryptor(t)
	newEnc, err := kms.NewAESGCMEncryptor(bytes.Repeat([]byte("n"), kms.KeySize))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}

	s := directory.New(db, oldEnc)
	ctx := context.Background()
	acct := mustCreateAccount(t, s)

	var created []directory.Vhost
	for i := 0; i < 3; i++ {
		v, err := s.CreateVhost(ctx, acct.ID, fmt.Sprintf("rotate-%d-%s.test", i, uuid.NewString()))
		if err != nil {
			t.Fatalf("CreateVhost: %v", err)
		}
		created = append(created, v)
	}

	rotated, err := s.RotateDKIMKeys(ctx, oldEnc, newEnc)
	if err != nil {
		t.Fatalf("RotateDKIMKeys: %v", err)
	}
	if rotated != len(created) {
		t.Fatalf("expected %d rows rotated, got %d", len(created), rotated)
	}

	oldReader := directory.New(db, oldEnc)
	if _, err := oldReader.GetVhost(ctx, created[0].ID); err == nil {
		t.Fatal("expected GetVhost under the old key to fail after rotation")
	}

	newReader := directory.New(db, newEnc)
	got, err := newReader.GetVhost(ctx, created[0].ID)
	if err != nil {
		t.Fatalf("GetVhost under new key: %v", err)
	}
	if got.DKIMKey == nil || got.DKIMKey.N.Cmp(created[0].DKIMKey.N) != 0 {
		t.Fatal("expected the same DKIM key material to round-trip through rotation")
	}

	// Idempotent resume: every row is already under newEnc, so re-running
	// with the same old/new pair rotates nothing rather than erroring.
	rotatedAgain, err := s.RotateDKIMKeys(ctx, oldEnc, newEnc)
	if err != nil {
		t.Fatalf("RotateDKIMKeys (resume): %v", err)
	}
	if rotatedAgain != 0 {
		t.Fatalf("expected 0 rows rotated on a resumed run (already migrated), got %d", rotatedAgain)
	}
}

// TestMigrateBackfillsLegacyAccountsIdempotently proves
// backfillLegacyAccounts (migrate.go): a vhost row with no account_id (the
// pre-account-scoping shape) gets its own fresh 1:1 "legacy" Account on the
// next Migrate call, and re-running Migrate again is a no-op — it doesn't
// create a second legacy account or touch the vhost's account_id a second
// time. Gated behind ENVELOPE_RUN_DESTRUCTIVE_TESTS and truncates
// accounts/vhosts/dkim_keys, the same reasoning and opt-in shape
// TestRotateDKIMKeys's doc above gives: this test's raw INSERT bypasses
// Service.CreateVhost (which always sets account_id today), so it can't
// rely on uniqueness-based isolation from concurrently running packages'
// test data the way the rest of this file does.
//
//	ENVELOPE_RUN_DESTRUCTIVE_TESTS=1 ENVELOPE_TEST_POSTGRES_DSN=... \
//	  go test ./internal/directory/... -run TestMigrateBackfillsLegacyAccountsIdempotently -v
func TestMigrateBackfillsLegacyAccountsIdempotently(t *testing.T) {
	if os.Getenv("ENVELOPE_RUN_DESTRUCTIVE_TESTS") == "" {
		t.Skip("ENVELOPE_RUN_DESTRUCTIVE_TESTS not set; skipping (see test doc to opt in)")
	}
	db := dbtest.DB(t)
	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	dbtest.Truncate(t, db, "dkim_keys", "vhosts", "accounts")

	// A prior successful Migrate run against this same long-lived database
	// (this test's own past runs, or any other package's) already tightened
	// account_id to NOT NULL once zero un-backfilled rows remained — dropping
	// it back here simulates the pre-account-scoping schema state this test
	// needs to seed a legacy row into, without which the INSERT below would
	// violate a constraint Migrate itself is responsible for re-applying.
	if err := db.Exec(`ALTER TABLE vhosts ALTER COLUMN account_id DROP NOT NULL`).Error; err != nil {
		t.Fatalf("simulate pre-backfill schema (drop NOT NULL): %v", err)
	}

	// Simulate a pre-account-scoping row: account_id is left out of the
	// INSERT entirely, landing NULL (the column is nullable precisely so
	// this state is representable pre-backfill — see vhostRow.AccountID's
	// doc).
	domain := "legacy-" + uuid.NewString() + ".test"
	vhostID := uuid.NewString()
	if err := db.Exec(`
		INSERT INTO vhosts (id, domain, active, max_message_bytes, daily_quota,
			spam_reject_threshold, spam_quarantine_threshold, retention_days, created_at, updated_at)
		VALUES ($1, $2, true, 0, 0, 0, 0, 0, now(), now())
	`, vhostID, domain).Error; err != nil {
		t.Fatalf("seed legacy vhost row: %v", err)
	}

	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate (backfill): %v", err)
	}

	s := directory.New(db, testEncryptor(t))
	v, err := s.GetVhost(context.Background(), vhostID)
	if err != nil {
		t.Fatalf("GetVhost: %v", err)
	}
	if v.AccountID == "" {
		t.Fatal("expected the legacy vhost to have a backfilled, non-empty AccountID")
	}

	acct, err := s.GetAccount(context.Background(), v.AccountID)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if acct.Name != "Legacy: "+domain {
		t.Fatalf("expected the backfilled account's name to reference the vhost's domain, got %q", acct.Name)
	}

	// Idempotent resume: re-running Migrate must not create a second legacy
	// account or reassign the vhost's account_id.
	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate (resume): %v", err)
	}
	vAgain, err := s.GetVhost(context.Background(), vhostID)
	if err != nil {
		t.Fatalf("GetVhost (after resume): %v", err)
	}
	if vAgain.AccountID != v.AccountID {
		t.Fatalf("expected AccountID to stay %q across a resumed Migrate, got %q", v.AccountID, vAgain.AccountID)
	}

	accounts, err := s.ListAccounts(context.Background(), "", directory.MaxVhostPageSize)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	legacyCount := 0
	for _, a := range accounts {
		if a.Name == "Legacy: "+domain {
			legacyCount++
		}
	}
	if legacyCount != 1 {
		t.Fatalf("expected exactly 1 legacy account for domain %q after a resumed Migrate, got %d", domain, legacyCount)
	}
}

func TestServiceVhostSurvivesNewConnection(t *testing.T) {
	// NFR-AV-2-style durability check for the Directory: data written
	// through one connection is visible through a completely separate
	// one, standing in for "survives a process restart" the way
	// internal/queue's equivalent test does.
	ctx := context.Background()
	db1 := dbtest.DB(t)
	if err := directory.Migrate(db1); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s1 := directory.New(db1, testEncryptor(t))
	acct := mustCreateAccount(t, s1)

	domain := uniqueDomain(t)
	if _, err := s1.CreateVhost(ctx, acct.ID, domain); err != nil {
		t.Fatalf("CreateVhost: %v", err)
	}

	db2 := dbtest.DB(t)
	s2 := directory.New(db2, testEncryptor(t))
	if !s2.VhostActive(ctx, domain) {
		t.Fatal("expected vhost created on one connection to be visible on another")
	}
}

// TestCreateVhostEncryptsDKIMKeyAtRest is TRD R1/NFR-SEC-3's actual
// empirical proof: querying the raw dkim_keys.private_key_pem column must
// not contain recognizable PEM plaintext. A bug that made encryptPEM a
// no-op would still pass every other test in this file (they all read
// back through Service, which would happily "decrypt" a value it never
// encrypted) — only inspecting the raw stored bytes catches that.
func TestCreateVhostEncryptsDKIMKeyAtRest(t *testing.T) {
	ctx := context.Background()
	db := dbtest.DB(t)
	if err := directory.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s := directory.New(db, testEncryptor(t))
	acct := mustCreateAccount(t, s)

	domain := uniqueDomain(t)
	v, err := s.CreateVhost(ctx, acct.ID, domain)
	if err != nil {
		t.Fatalf("CreateVhost: %v", err)
	}
	if v.DKIMKey == nil {
		t.Fatal("expected CreateVhost to return the decoded DKIM key")
	}

	var storedPEM string
	if err := db.Table("dkim_keys").Select("private_key_pem").
		Where("vhost_id = ?", v.ID).Scan(&storedPEM).Error; err != nil {
		t.Fatalf("query raw private_key_pem: %v", err)
	}
	if storedPEM == "" {
		t.Fatal("expected a stored private_key_pem value")
	}
	if bytes.Contains([]byte(storedPEM), []byte("PRIVATE KEY")) {
		t.Fatalf("private_key_pem is stored as plaintext PEM, not encrypted: %s", storedPEM)
	}
}
