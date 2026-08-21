package webhook_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/envelope-mx/envelope/internal/webhook"
)

func TestEventQueueEnqueueDequeueComplete(t *testing.T) {
	ctx := context.Background()
	q := webhook.NewMemoryEventQueue()

	job := webhook.DeliveryJob{ID: "1", SubscriptionID: "sub-1", URL: "https://a.example/hook", EventType: "message.received"}
	if err := q.Enqueue(ctx, job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	got, ok, err := q.Dequeue(ctx)
	if err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}
	if got.ID != "1" || got.SubscriptionID != "sub-1" {
		t.Fatalf("got job %+v", got)
	}

	if err := q.Complete(ctx, "1"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, ok, err := q.Dequeue(ctx); err != nil || ok {
		t.Fatalf("expected empty queue after Complete, ok=%v err=%v", ok, err)
	}
}

func TestEventQueueDequeueDoesNotDoubleClaim(t *testing.T) {
	ctx := context.Background()
	q := webhook.NewMemoryEventQueue()

	if err := q.Enqueue(ctx, webhook.DeliveryJob{ID: "1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, ok, err := q.Dequeue(ctx); err != nil || !ok {
		t.Fatalf("first Dequeue: ok=%v err=%v", ok, err)
	}
	if _, ok, err := q.Dequeue(ctx); err != nil || ok {
		t.Fatalf("second Dequeue should find no unclaimed job: ok=%v err=%v", ok, err)
	}
}

func TestEventQueueFailReschedules(t *testing.T) {
	ctx := context.Background()
	q := webhook.NewMemoryEventQueue()

	if err := q.Enqueue(ctx, webhook.DeliveryJob{ID: "1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, ok, err := q.Dequeue(ctx); err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}

	if err := q.Fail(ctx, "1", errors.New("connection refused"), time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	got, ok, err := q.Dequeue(ctx)
	if err != nil || !ok {
		t.Fatalf("Dequeue after Fail: ok=%v err=%v", ok, err)
	}
	if got.Attempts != 1 || got.LastError != "connection refused" {
		t.Fatalf("unexpected job state after Fail: %+v", got)
	}
}

func TestEventQueueCompleteUnknownJobErrors(t *testing.T) {
	q := webhook.NewMemoryEventQueue()
	if err := q.Complete(context.Background(), "missing"); err == nil {
		t.Fatal("expected error completing an unknown job")
	}
}
