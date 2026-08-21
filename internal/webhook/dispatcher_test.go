package webhook_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/isaiahiroko/envelope/internal/webhook"
)

func newTestDispatcher(store *webhook.MemoryStore, q *webhook.MemoryEventQueue) *webhook.Dispatcher {
	d := webhook.NewDispatcher(store, q)
	// Fast retry timing so tests don't wait on real backoff durations.
	d.BackoffBase = time.Millisecond
	d.BackoffMax = 5 * time.Millisecond
	d.PollInterval = 2 * time.Millisecond
	return d
}

func TestEnqueueFansOutToMatchingEnabledSubscriptions(t *testing.T) {
	ctx := context.Background()
	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	d := newTestDispatcher(store, q)

	if err := store.CreateSubscription(ctx, webhook.Subscription{
		ID: "matches-type", Vhost: "a.example", URL: "https://a.example/hook",
		EventTypes: []string{webhook.EventMessageReceived},
	}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := store.CreateSubscription(ctx, webhook.Subscription{
		ID: "wrong-type", Vhost: "a.example", URL: "https://a.example/hook2",
		EventTypes: []string{webhook.EventMessageBounced},
	}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := store.CreateSubscription(ctx, webhook.Subscription{
		ID: "disabled", Vhost: "a.example", URL: "https://a.example/hook3", Disabled: true,
	}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := store.CreateSubscription(ctx, webhook.Subscription{
		ID: "other-vhost", Vhost: "b.example", URL: "https://b.example/hook",
	}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	if err := d.Enqueue(ctx, "a.example", webhook.EventMessageReceived, []byte(`{}`)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	var got []webhook.DeliveryJob
	for {
		job, ok, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("Dequeue: %v", err)
		}
		if !ok {
			break
		}
		got = append(got, job)
	}
	if len(got) != 1 || got[0].SubscriptionID != "matches-type" {
		t.Fatalf("expected exactly one fanned-out job for the matching subscription, got %+v", got)
	}
}

func TestDispatcherDeliversAndSignsPayload(t *testing.T) {
	ctx := context.Background()
	var receivedSig, receivedEvent string
	var receivedBody []byte
	done := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		receivedSig = r.Header.Get("X-Envelope-Signature")
		receivedEvent = r.Header.Get("X-Envelope-Event")
		w.WriteHeader(http.StatusOK)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	d := newTestDispatcher(store, q)

	const secret = "s3cret"
	if err := store.CreateSubscription(ctx, webhook.Subscription{ID: "sub-1", Vhost: "a.example", URL: srv.URL, Secret: secret}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	payload, err := webhook.NewEventPayload("evt-1", webhook.EventMessageDelivered, "a.example", map[string]string{"to": "bob@a.example"})
	if err != nil {
		t.Fatalf("NewEventPayload: %v", err)
	}
	if err := d.Enqueue(ctx, "a.example", webhook.EventMessageDelivered, payload); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		d.Run(runCtx)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery")
	}
	waitForQueueEmpty(t, ctx, q)
	cancel()
	<-runDone

	if receivedEvent != webhook.EventMessageDelivered {
		t.Fatalf("X-Envelope-Event = %q, want %q", receivedEvent, webhook.EventMessageDelivered)
	}
	if !webhook.Verify(secret, receivedBody, receivedSig) {
		t.Fatalf("delivered payload signature did not verify: sig=%q body=%s", receivedSig, receivedBody)
	}

	attempts, err := store.ListAttempts(ctx, "a.example", "sub-1")
	if err != nil {
		t.Fatalf("ListAttempts: %v", err)
	}
	if len(attempts) != 1 || attempts[0].StatusCode != http.StatusOK {
		t.Fatalf("unexpected attempt history: %+v", attempts)
	}
}

func TestDispatcherRetriesThenSucceeds(t *testing.T) {
	ctx := context.Background()
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	d := newTestDispatcher(store, q)

	if err := store.CreateSubscription(ctx, webhook.Subscription{ID: "sub-1", Vhost: "a.example", URL: srv.URL, Secret: "s"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := d.Enqueue(ctx, "a.example", webhook.EventMessageDelivered, []byte(`{}`)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		d.Run(runCtx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	waitForQueueEmpty(t, ctx, q)
	cancel()
	<-runDone

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected exactly 3 delivery attempts (2 failures + 1 success), got %d", got)
	}
	attempts, err := store.ListAttempts(ctx, "a.example", "sub-1")
	if err != nil {
		t.Fatalf("ListAttempts: %v", err)
	}
	if len(attempts) != 3 {
		t.Fatalf("expected 3 recorded attempts, got %+v", attempts)
	}
	if attempts[2].StatusCode != http.StatusOK {
		t.Fatalf("expected final attempt to succeed, got %+v", attempts[2])
	}
}

func TestDispatcherDeadLettersAfterMaxAttempts(t *testing.T) {
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	d := newTestDispatcher(store, q)
	d.MaxAttempts = 3

	if err := store.CreateSubscription(ctx, webhook.Subscription{ID: "sub-1", Vhost: "a.example", URL: srv.URL, Secret: "s"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := d.Enqueue(ctx, "a.example", webhook.EventMessageBounced, []byte(`{}`)); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		d.Run(runCtx)
	}()

	waitForQueueEmpty(t, ctx, q)
	cancel()
	<-runDone

	attempts, err := store.ListAttempts(ctx, "a.example", "sub-1")
	if err != nil {
		t.Fatalf("ListAttempts: %v", err)
	}
	if len(attempts) != d.MaxAttempts {
		t.Fatalf("expected dead-letter after exactly %d attempts, got %d: %+v", d.MaxAttempts, len(attempts), attempts)
	}
	for _, a := range attempts {
		if a.StatusCode != http.StatusInternalServerError {
			t.Fatalf("unexpected attempt: %+v", a)
		}
	}
}

// TestDispatcherRedriveRetriesDeadLetteredEvent is docs/RUNBOOK.md §4.3's
// closed gap: an event that dead-lettered after MaxAttempts can be
// manually redriven and, if the endpoint recovers, delivered.
func TestDispatcherRedriveRetriesDeadLetteredEvent(t *testing.T) {
	ctx := context.Background()

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 3 { // fails every original attempt through dead-letter
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK) // succeeds on the redriven attempt
	}))
	defer srv.Close()

	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	d := newTestDispatcher(store, q)
	d.MaxAttempts = 3

	if err := store.CreateSubscription(ctx, webhook.Subscription{ID: "sub-1", Vhost: "a.example", URL: srv.URL, Secret: "s"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	payload, err := webhook.NewEventPayload("evt-1", webhook.EventMessageBounced, "a.example", map[string]string{"to": "bob@a.example"})
	if err != nil {
		t.Fatalf("NewEventPayload: %v", err)
	}
	if err := d.Enqueue(ctx, "a.example", webhook.EventMessageBounced, payload); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	runOnce := func() {
		runCtx, cancel := context.WithCancel(ctx)
		runDone := make(chan struct{})
		go func() {
			defer close(runDone)
			d.Run(runCtx)
		}()
		waitForQueueEmpty(t, ctx, q)
		cancel()
		<-runDone
	}
	runOnce()

	attempts, err := store.ListAttempts(ctx, "a.example", "sub-1")
	if err != nil {
		t.Fatalf("ListAttempts: %v", err)
	}
	if len(attempts) != d.MaxAttempts {
		t.Fatalf("expected dead-letter after %d attempts, got %d: %+v", d.MaxAttempts, len(attempts), attempts)
	}
	eventID := attempts[0].EventID

	if err := d.Redrive(ctx, "a.example", "sub-1", eventID); err != nil {
		t.Fatalf("Redrive: %v", err)
	}
	runOnce()

	finalAttempts, err := store.ListAttempts(ctx, "a.example", "sub-1")
	if err != nil {
		t.Fatalf("ListAttempts after redrive: %v", err)
	}
	if len(finalAttempts) != d.MaxAttempts+1 {
		t.Fatalf("expected %d total attempts after redrive, got %d: %+v", d.MaxAttempts+1, len(finalAttempts), finalAttempts)
	}
	last := finalAttempts[len(finalAttempts)-1]
	if last.StatusCode != http.StatusOK {
		t.Fatalf("expected the redriven attempt to succeed, got %+v", last)
	}
	if last.EventID != eventID {
		t.Fatalf("expected the redriven attempt to carry the original event ID, got %q want %q", last.EventID, eventID)
	}
}

func TestDispatcherRedriveUnknownEventReturnsErrNotFound(t *testing.T) {
	ctx := context.Background()
	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	d := newTestDispatcher(store, q)

	if err := store.CreateSubscription(ctx, webhook.Subscription{ID: "sub-1", Vhost: "a.example", URL: "https://a.example/hook", Secret: "s"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}

	if err := d.Redrive(ctx, "a.example", "sub-1", "never-happened"); !errors.Is(err, webhook.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDispatcherRedriveUnknownSubscriptionReturnsErrNotFound(t *testing.T) {
	ctx := context.Background()
	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	d := newTestDispatcher(store, q)

	if err := d.Redrive(ctx, "a.example", "does-not-exist", "evt-1"); !errors.Is(err, webhook.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDispatcherRedriveDisabledSubscriptionErrors(t *testing.T) {
	ctx := context.Background()
	store := webhook.NewMemoryStore()
	q := webhook.NewMemoryEventQueue()
	d := newTestDispatcher(store, q)

	if err := store.CreateSubscription(ctx, webhook.Subscription{ID: "sub-1", Vhost: "a.example", URL: "https://a.example/hook", Secret: "s"}); err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if err := store.DisableSubscription(ctx, "a.example", "sub-1"); err != nil {
		t.Fatalf("DisableSubscription: %v", err)
	}

	if err := d.Redrive(ctx, "a.example", "sub-1", "evt-1"); err == nil {
		t.Fatal("expected an error redriving to a disabled subscription")
	}
}

// waitForQueueEmpty polls q until Dequeue reports nothing due — Run's
// background goroutine has finished processing everything it will process
// for the duration of this test (either delivered, or dead-lettered).
func waitForQueueEmpty(t *testing.T, ctx context.Context, q *webhook.MemoryEventQueue) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if q.Empty() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the delivery queue to drain")
}
