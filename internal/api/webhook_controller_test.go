package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/webhook"
)

func TestWebhookSubscriptionCRUDAndAttempts(t *testing.T) {
	svc := newService(t)
	store := webhook.NewMemoryStore()
	base, admin := startAPIWithWebhooks(t, svc, store)
	accountID, _ := createAccount(t, base, admin)

	// Create vhost to attach the subscription to.
	vhostID := createVhost(t, base, admin, accountID, t.Name()+"-"+uuid.NewString()+".test")

	// Create subscription under an unknown vhost -> 404.
	status, _ := doJSON(t, http.MethodPost, base+"/vhosts/does-not-exist/webhooks", admin,
		map[string]any{"url": "https://example.test/hook", "secret": "s3cret"})
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 creating subscription under unknown vhost, got %d", status)
	}

	// Create subscription.
	status, resp := doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/webhooks", admin,
		map[string]any{"url": "https://example.test/hook", "secret": "s3cret", "eventTypes": []string{"message.delivered"}})
	if status != http.StatusCreated {
		t.Fatalf("create subscription: status=%d body=%v", status, resp)
	}
	sub := resp["data"].(map[string]any)
	subID, _ := sub["id"].(string)
	if subID == "" || sub["url"] != "https://example.test/hook" {
		t.Fatalf("unexpected created subscription: %+v", sub)
	}
	if _, leaked := sub["secret"]; leaked {
		t.Fatalf("response leaked the subscription secret: %+v", sub)
	}

	// List subscriptions.
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/webhooks", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list subscriptions: status=%d body=%v", status, resp)
	}
	list, _ := resp["data"].([]any)
	if len(list) != 1 {
		t.Fatalf("expected 1 subscription, got %+v", list)
	}

	// No delivery attempts yet.
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/webhooks/"+subID+"/attempts", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list attempts: status=%d body=%v", status, resp)
	}
	if attempts, _ := resp["data"].([]any); len(attempts) != 0 {
		t.Fatalf("expected no attempts yet, got %+v", attempts)
	}

	// Record a delivery attempt directly through the store (standing in for
	// what Dispatcher.Run does), then confirm it surfaces via the API
	// (FR-6.4's dead-letter visibility).
	if err := store.RecordAttempt(t.Context(), webhook.DeliveryAttempt{
		Vhost: vhostID, SubscriptionID: subID, EventID: "evt-1", Attempt: 1, StatusCode: 500, Error: "boom",
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/webhooks/"+subID+"/attempts", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list attempts: status=%d body=%v", status, resp)
	}
	attempts, _ := resp["data"].([]any)
	if len(attempts) != 1 || attempts[0].(map[string]any)["statusCode"] != float64(500) {
		t.Fatalf("unexpected attempts: %+v", attempts)
	}

	// Attempts under the wrong vhost are isolated (FR-1.5): a second vhost
	// asking for this subscription's history sees nothing.
	otherVhostID := createVhost(t, base, admin, accountID, t.Name()+"-other-"+uuid.NewString()+".test")
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+otherVhostID+"/webhooks/"+subID+"/attempts", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list attempts under other vhost: status=%d body=%v", status, resp)
	}
	if attempts, _ := resp["data"].([]any); len(attempts) != 0 {
		t.Fatalf("expected cross-vhost attempt lookup to see nothing, got %+v", attempts)
	}

	// Disabling under the wrong vhost fails.
	status, _ = doJSON(t, http.MethodPatch, base+"/vhosts/"+otherVhostID+"/webhooks/"+subID+"/disable", admin, nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 disabling subscription under the wrong vhost, got %d", status)
	}

	// Disable subscription (FR-6.5).
	status, _ = doJSON(t, http.MethodPatch, base+"/vhosts/"+vhostID+"/webhooks/"+subID+"/disable", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("disable subscription: status=%d", status)
	}
	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/webhooks", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list subscriptions after disable: status=%d body=%v", status, resp)
	}
	list, _ = resp["data"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["disabled"] != true {
		t.Fatalf("expected subscription still present and disabled: %+v", list)
	}
}

// TestWebhookRedriveAttempt is docs/RUNBOOK.md §4.3's closed gap, exercised
// end to end over real HTTP: a dead-lettered event can be manually
// redriven via POST .../attempts/:eventId/redrive and, once the endpoint
// recovers, delivered.
func TestWebhookRedriveAttempt(t *testing.T) {
	svc := newService(t)
	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	dispatcher := webhook.NewDispatcher(store, q)
	dispatcher.BackoffBase = time.Millisecond
	dispatcher.BackoffMax = 5 * time.Millisecond
	dispatcher.PollInterval = 2 * time.Millisecond
	dispatcher.MaxAttempts = 2

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 2 { // fails every original attempt through dead-letter
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK) // succeeds on the redriven attempt
	}))
	defer srv.Close()

	base, admin := startAPIWithRedrive(t, svc, store, dispatcher)
	accountID, _ := createAccount(t, base, admin)
	domain := t.Name() + "-" + uuid.NewString() + ".test"
	vhostID := createVhost(t, base, admin, accountID, domain)

	status, resp := doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/webhooks", admin,
		map[string]any{"url": srv.URL, "secret": "s3cret"})
	if status != http.StatusCreated {
		t.Fatalf("create subscription: status=%d body=%v", status, resp)
	}
	subID := resp["data"].(map[string]any)["id"].(string)

	runDispatcherUntilQueueEmpty := func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			dispatcher.Run(ctx)
		}()
		deadline := time.Now().Add(2 * time.Second)
		for !q.Empty() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		<-done
	}

	if err := dispatcher.Enqueue(context.Background(), domain, webhook.EventMessageBounced, []byte(`{}`)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	runDispatcherUntilQueueEmpty()

	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/webhooks/"+subID+"/attempts", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list attempts: status=%d body=%v", status, resp)
	}
	attempts, _ := resp["data"].([]any)
	if len(attempts) != 2 {
		t.Fatalf("expected 2 dead-lettering attempts, got %+v", attempts)
	}
	eventID := attempts[0].(map[string]any)["eventId"].(string)

	// Redrive under the wrong vhost 404s (FR-1.5).
	otherVhostID := createVhost(t, base, admin, accountID, t.Name()+"-other-"+uuid.NewString()+".test")
	status, _ = doJSON(t, http.MethodPost, base+"/vhosts/"+otherVhostID+"/webhooks/"+subID+"/attempts/"+eventID+"/redrive", admin, nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 redriving under the wrong vhost, got %d", status)
	}

	// Redriving an event that was never attempted 404s.
	status, _ = doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/webhooks/"+subID+"/attempts/never-happened/redrive", admin, nil)
	if status != http.StatusNotFound {
		t.Fatalf("expected 404 redriving an unknown event, got %d", status)
	}

	// The real redrive.
	status, resp = doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/webhooks/"+subID+"/attempts/"+eventID+"/redrive", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("redrive: status=%d body=%v", status, resp)
	}
	runDispatcherUntilQueueEmpty()

	status, resp = doJSON(t, http.MethodGet, base+"/vhosts/"+vhostID+"/webhooks/"+subID+"/attempts", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("list attempts after redrive: status=%d body=%v", status, resp)
	}
	finalAttempts, _ := resp["data"].([]any)
	if len(finalAttempts) != 3 {
		t.Fatalf("expected 3 total attempts after redrive, got %+v", finalAttempts)
	}
	last := finalAttempts[len(finalAttempts)-1].(map[string]any)
	if last["statusCode"] != float64(http.StatusOK) {
		t.Fatalf("expected the redriven attempt to succeed, got %+v", last)
	}
	if last["eventId"] != eventID {
		t.Fatalf("expected the redriven attempt to carry the original event ID, got %+v", last)
	}
}

// TestWebhookRedriveWithoutDispatcherReturns503 covers RedrivePolicy's
// zero-value case (see that type's doc): a deployment/test that never
// registers one gets a clear 503, not a nil-pointer panic.
func TestWebhookRedriveWithoutDispatcherReturns503(t *testing.T) {
	svc := newService(t)
	store := webhook.NewMemoryStore()
	base, admin := startAPIWithWebhooks(t, svc, store) // no RedrivePolicy registered
	accountID, _ := createAccount(t, base, admin)
	vhostID := createVhost(t, base, admin, accountID, t.Name()+"-"+uuid.NewString()+".test")

	status, resp := doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/webhooks", admin,
		map[string]any{"url": "https://example.test/hook", "secret": "s3cret"})
	if status != http.StatusCreated {
		t.Fatalf("create subscription: status=%d body=%v", status, resp)
	}
	subID := resp["data"].(map[string]any)["id"].(string)

	status, _ = doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/webhooks/"+subID+"/attempts/evt-1/redrive", admin, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 with no Dispatcher wired, got %d", status)
	}
}

func TestCreateWebhookSubscriptionRejectsMissingFields(t *testing.T) {
	svc := newService(t)
	store := webhook.NewMemoryStore()
	base, admin := startAPIWithWebhooks(t, svc, store)
	accountID, _ := createAccount(t, base, admin)
	vhostID := createVhost(t, base, admin, accountID, t.Name()+"-"+uuid.NewString()+".test")

	status, _ := doJSON(t, http.MethodPost, base+"/vhosts/"+vhostID+"/webhooks", admin, map[string]any{"url": "", "secret": ""})
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing url/secret, got %d", status)
	}
}
