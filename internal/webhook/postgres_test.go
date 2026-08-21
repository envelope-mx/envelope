package webhook_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/isaiahiroko/envelope/internal/dbtest"
	"github.com/isaiahiroko/envelope/internal/kms"
	"github.com/isaiahiroko/envelope/internal/webhook"
)

func newPostgresStore(t *testing.T) *webhook.PostgresStore {
	t.Helper()
	store, _ := newPostgresStoreWithDB(t)
	return store
}

func newPostgresStoreWithDB(t *testing.T) (*webhook.PostgresStore, *gorm.DB) {
	t.Helper()
	db := dbtest.DB(t)
	if err := webhook.MigratePostgres(db); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	dbtest.Truncate(t, db, "webhook_delivery_attempts", "webhook_subscriptions")
	enc, err := kms.NewAESGCMEncryptor(bytes.Repeat([]byte("k"), kms.KeySize))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	return webhook.NewPostgresStore(db, enc), db
}

func TestPostgresCreateAndListSubscriptions(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)

	id1, id2 := uuid.NewString(), uuid.NewString()
	if err := s.CreateSubscription(ctx, webhook.Subscription{
		ID: id1, Vhost: "a.example", URL: "https://a.example/hook", EventTypes: []string{"message.received"},
	}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: id2, Vhost: "b.example", URL: "https://b.example/hook"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	subs, err := s.ListSubscriptions(ctx, "a.example")
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != id1 || len(subs[0].EventTypes) != 1 || subs[0].EventTypes[0] != "message.received" {
		t.Fatalf("unexpected subscriptions: %+v", subs)
	}
}

func TestPostgresDisableSubscriptionPreservesHistory(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)

	id := uuid.NewString()
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: id, Vhost: "a.example"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := s.RecordAttempt(ctx, webhook.DeliveryAttempt{SubscriptionID: id, EventID: "e1", Attempt: 1, StatusCode: 500, AttemptedAt: time.Now()}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	if err := s.DisableSubscription(ctx, "a.example", id); err != nil {
		t.Fatalf("DisableSubscription: %v", err)
	}

	subs, err := s.ListSubscriptions(ctx, "a.example")
	if err != nil || len(subs) != 1 || !subs[0].Disabled {
		t.Fatalf("expected subscription still present and disabled: %+v (err %v)", subs, err)
	}

	attempts, err := s.ListAttempts(ctx, "a.example", id)
	if err != nil || len(attempts) != 1 {
		t.Fatalf("expected delivery history preserved after disable: %+v (err %v)", attempts, err)
	}
}

func TestPostgresDisableUnknownSubscriptionErrors(t *testing.T) {
	s := newPostgresStore(t)
	if err := s.DisableSubscription(context.Background(), "a.example", uuid.NewString()); err == nil {
		t.Fatal("expected error disabling an unknown subscription")
	}
}

func TestPostgresListAttemptsOrder(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)

	id := uuid.NewString()
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: id, Vhost: "a.example"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	base := time.Now()
	for i := 1; i <= 3; i++ {
		if err := s.RecordAttempt(ctx, webhook.DeliveryAttempt{
			SubscriptionID: id, EventID: "e1", Attempt: i, AttemptedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("RecordAttempt %d: %v", i, err)
		}
	}

	attempts, err := s.ListAttempts(ctx, "a.example", id)
	if err != nil {
		t.Fatalf("ListAttempts: %v", err)
	}
	if len(attempts) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(attempts))
	}
	for i, a := range attempts {
		if a.Attempt != i+1 {
			t.Fatalf("attempts out of order: %+v", attempts)
		}
	}
}

// TestPostgresListSubscriptionsPage exercises FR-5.4's cursor pagination
// the same way internal/directory's TestListMailboxesPage does: every
// subscription must appear exactly once across the full sweep, regardless
// of page boundaries.
func TestPostgresListSubscriptionsPage(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)

	const total = 5
	for i := 0; i < total; i++ {
		if err := s.CreateSubscription(ctx, webhook.Subscription{
			ID: uuid.NewString(), Vhost: "a.example", URL: "https://a.example/hook",
		}); err != nil {
			t.Fatalf("CreateSubscription %d: %v", i, err)
		}
	}
	// A different vhost's subscription must never appear in a.example's
	// pages (FR-1.5), regardless of page boundaries.
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: uuid.NewString(), Vhost: "b.example", URL: "https://b.example/hook"}); err != nil {
		t.Fatalf("CreateSubscription (other vhost): %v", err)
	}

	seen := make(map[string]bool)
	cursor := ""
	for {
		page, err := s.ListSubscriptionsPage(ctx, "a.example", cursor, 2)
		if err != nil {
			t.Fatalf("ListSubscriptionsPage: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, sub := range page {
			if seen[sub.ID] {
				t.Fatalf("subscription %q returned on more than one page", sub.ID)
			}
			seen[sub.ID] = true
		}
		if len(page) < 2 {
			break
		}
		cursor = page[len(page)-1].ID
	}

	if len(seen) != total {
		t.Fatalf("expected %d distinct subscriptions across all pages, got %d", total, len(seen))
	}
}

// TestPostgresListAttemptsPage is TestPostgresListSubscriptionsPage's
// counterpart for delivery attempts, using the same full-sweep-finds-every-
// row-exactly-once assertion.
func TestPostgresListAttemptsPage(t *testing.T) {
	ctx := context.Background()
	s := newPostgresStore(t)

	id := uuid.NewString()
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: id, Vhost: "a.example"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	const total = 5
	base := time.Now()
	for i := 1; i <= total; i++ {
		if err := s.RecordAttempt(ctx, webhook.DeliveryAttempt{
			SubscriptionID: id, EventID: "e1", Attempt: i, AttemptedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("RecordAttempt %d: %v", i, err)
		}
	}

	seen := make(map[string]bool)
	var order []int
	cursor := ""
	for {
		page, err := s.ListAttemptsPage(ctx, "a.example", id, cursor, 2)
		if err != nil {
			t.Fatalf("ListAttemptsPage: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, a := range page {
			if seen[a.ID] {
				t.Fatalf("attempt %q returned on more than one page", a.ID)
			}
			seen[a.ID] = true
			order = append(order, a.Attempt)
		}
		if len(page) < 2 {
			break
		}
		cursor = page[len(page)-1].ID
	}

	if len(seen) != total {
		t.Fatalf("expected %d distinct attempts across all pages, got %d", total, len(seen))
	}
	for i, attemptNum := range order {
		if attemptNum != i+1 {
			t.Fatalf("expected attempts in oldest-first order across pages, got %v", order)
		}
	}
}

// TestPostgresRotateSecrets is the webhook half of the master-key rotation
// tool (cmd/envelope/main.go's --rotate-master-key; see
// directory.TestRotateDKIMKeys for the DKIM half). Unlike that test, this
// one needs no destructive-test opt-in: newPostgresStore already truncates
// webhook_subscriptions before every test in this file, so rotating
// everything in the table is scoped to this test's own rows.
func TestPostgresRotateSecrets(t *testing.T) {
	ctx := context.Background()
	oldEnc, err := kms.NewAESGCMEncryptor(bytes.Repeat([]byte("k"), kms.KeySize))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor (old): %v", err)
	}
	newEnc, err := kms.NewAESGCMEncryptor(bytes.Repeat([]byte("n"), kms.KeySize))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor (new): %v", err)
	}

	db := dbtest.DB(t)
	if err := webhook.MigratePostgres(db); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	dbtest.Truncate(t, db, "webhook_delivery_attempts", "webhook_subscriptions")
	s := webhook.NewPostgresStore(db, oldEnc)

	var created []string
	for i := 0; i < 3; i++ {
		id := uuid.NewString()
		if err := s.CreateSubscription(ctx, webhook.Subscription{
			ID: id, Vhost: "a.example", URL: "https://a.example/hook", Secret: "s3cret",
		}); err != nil {
			t.Fatalf("CreateSubscription: %v", err)
		}
		created = append(created, id)
	}

	rotated, err := s.RotateSecrets(ctx, oldEnc, newEnc)
	if err != nil {
		t.Fatalf("RotateSecrets: %v", err)
	}
	if rotated != len(created) {
		t.Fatalf("expected %d rows rotated, got %d", len(created), rotated)
	}

	oldReader := webhook.NewPostgresStore(db, oldEnc)
	if _, err := oldReader.ListSubscriptions(ctx, "a.example"); err == nil {
		t.Fatal("expected ListSubscriptions under the old key to fail decrypting after rotation")
	}

	newReader := webhook.NewPostgresStore(db, newEnc)
	subs, err := newReader.ListSubscriptions(ctx, "a.example")
	if err != nil {
		t.Fatalf("ListSubscriptions under new key: %v", err)
	}
	if len(subs) != len(created) {
		t.Fatalf("expected %d subscriptions, got %d", len(created), len(subs))
	}
	for _, sub := range subs {
		if sub.Secret != "s3cret" {
			t.Fatalf("expected the original secret to round-trip through rotation, got %q", sub.Secret)
		}
	}

	// Idempotent resume: every row is already under newEnc.
	rotatedAgain, err := s.RotateSecrets(ctx, oldEnc, newEnc)
	if err != nil {
		t.Fatalf("RotateSecrets (resume): %v", err)
	}
	if rotatedAgain != 0 {
		t.Fatalf("expected 0 rows rotated on a resumed run (already migrated), got %d", rotatedAgain)
	}
}

// TestCreateSubscriptionEncryptsSecretAtRest is TRD R1/NFR-SEC-3's actual
// empirical proof for webhook secrets, the same way
// internal/directory's TestCreateVhostEncryptsDKIMKeyAtRest is for DKIM
// keys: the raw stored column must not equal the plaintext secret.
func TestCreateSubscriptionEncryptsSecretAtRest(t *testing.T) {
	ctx := context.Background()
	s, db := newPostgresStoreWithDB(t)

	id := uuid.NewString()
	const plaintextSecret = "whsec_super_secret_value"
	if err := s.CreateSubscription(ctx, webhook.Subscription{
		ID: id, Vhost: "a.example", URL: "https://a.example/hook", Secret: plaintextSecret,
	}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	var storedSecret string
	if err := db.Table("webhook_subscriptions").Select("secret").
		Where("id = ?", id).Scan(&storedSecret).Error; err != nil {
		t.Fatalf("query raw secret: %v", err)
	}
	if storedSecret == "" {
		t.Fatal("expected a stored secret value")
	}
	if storedSecret == plaintextSecret {
		t.Fatal("secret is stored in plaintext, not encrypted")
	}

	subs, err := s.ListSubscriptions(ctx, "a.example")
	if err != nil || len(subs) != 1 || subs[0].Secret != plaintextSecret {
		t.Fatalf("expected the decrypted secret to round-trip through ListSubscriptions: %+v (err %v)", subs, err)
	}
}
