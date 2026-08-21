package webhook_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/envelope-mx/envelope/internal/webhook"
)

func TestCreateAndListSubscriptions(t *testing.T) {
	ctx := context.Background()
	s := webhook.NewMemoryStore()

	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: "1", Vhost: "a.example", URL: "https://a.example/hook"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: "2", Vhost: "b.example", URL: "https://b.example/hook"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	subs, err := s.ListSubscriptions(ctx, "a.example")
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(subs) != 1 || subs[0].ID != "1" {
		t.Fatalf("unexpected subscriptions: %+v", subs)
	}
}

func TestDisableSubscriptionPreservesHistory(t *testing.T) {
	ctx := context.Background()
	s := webhook.NewMemoryStore()

	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: "1", Vhost: "a.example"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := s.RecordAttempt(ctx, webhook.DeliveryAttempt{SubscriptionID: "1", EventID: "e1", Attempt: 1, StatusCode: 500, AttemptedAt: time.Now()}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}

	if err := s.DisableSubscription(ctx, "a.example", "1"); err != nil {
		t.Fatalf("DisableSubscription: %v", err)
	}

	subs, err := s.ListSubscriptions(ctx, "a.example")
	if err != nil || len(subs) != 1 || !subs[0].Disabled {
		t.Fatalf("expected subscription still present and disabled: %+v (err %v)", subs, err)
	}

	attempts, err := s.ListAttempts(ctx, "a.example", "1")
	if err != nil || len(attempts) != 1 {
		t.Fatalf("expected delivery history preserved after disable: %+v (err %v)", attempts, err)
	}
}

func TestDisableUnknownSubscriptionErrors(t *testing.T) {
	s := webhook.NewMemoryStore()
	if err := s.DisableSubscription(context.Background(), "a.example", "missing"); err == nil {
		t.Fatal("expected error disabling an unknown subscription")
	}
}

func TestListSubscriptionsPageSweepFindsEveryRowOnce(t *testing.T) {
	ctx := context.Background()
	s := webhook.NewMemoryStore()

	const total = 5
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("sub-%d", i)
		if err := s.CreateSubscription(ctx, webhook.Subscription{ID: id, Vhost: "a.example", URL: "https://a.example/hook"}); err != nil {
			t.Fatalf("CreateSubscription %d: %v", i, err)
		}
	}
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: "other", Vhost: "b.example"}); err != nil {
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

func TestListAttemptsPageSweepFindsEveryRowOnce(t *testing.T) {
	ctx := context.Background()
	s := webhook.NewMemoryStore()
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: "1", Vhost: "a.example"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	const total = 5
	for i := 1; i <= total; i++ {
		if err := s.RecordAttempt(ctx, webhook.DeliveryAttempt{SubscriptionID: "1", EventID: "e1", Attempt: i}); err != nil {
			t.Fatalf("RecordAttempt %d: %v", i, err)
		}
	}

	seen := make(map[string]bool)
	var order []int
	cursor := ""
	for {
		page, err := s.ListAttemptsPage(ctx, "a.example", "1", cursor, 2)
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

func TestRecordAndListAttemptsOrder(t *testing.T) {
	ctx := context.Background()
	s := webhook.NewMemoryStore()
	if err := s.CreateSubscription(ctx, webhook.Subscription{ID: "1", Vhost: "a.example"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	for i := 1; i <= 3; i++ {
		if err := s.RecordAttempt(ctx, webhook.DeliveryAttempt{SubscriptionID: "1", EventID: "e1", Attempt: i}); err != nil {
			t.Fatalf("RecordAttempt %d: %v", i, err)
		}
	}

	attempts, err := s.ListAttempts(ctx, "a.example", "1")
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
