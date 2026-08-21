package webhook_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/envelope-mx/envelope/internal/dbtest"
	"github.com/envelope-mx/envelope/internal/webhook"
)

func newPostgresEventQueue(t *testing.T) *webhook.PostgresEventQueue {
	t.Helper()
	db := dbtest.DB(t)
	if err := webhook.MigratePostgres(db); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	dbtest.Truncate(t, db, "webhook_deliveries")
	return webhook.NewPostgresEventQueue(db)
}

func TestPostgresEventQueueEnqueueDequeueComplete(t *testing.T) {
	ctx := context.Background()
	q := newPostgresEventQueue(t)

	id := uuid.NewString()
	job := webhook.DeliveryJob{
		ID: id, SubscriptionID: "sub-1", URL: "https://a.example/hook", Secret: "s3cret",
		EventID: "evt-1", EventType: "message.received", Payload: []byte(`{"ok":true}`),
		NextAttemptAt: time.Now().Add(-time.Second),
	}
	if err := q.Enqueue(ctx, job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	got, ok, err := q.Dequeue(ctx)
	if err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}
	if got.URL != job.URL || got.Secret != job.Secret || string(got.Payload) != string(job.Payload) {
		t.Fatalf("unexpected job: %+v", got)
	}

	if err := q.Complete(ctx, id); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, ok, err := q.Dequeue(ctx); err != nil || ok {
		t.Fatalf("expected empty queue after Complete, ok=%v err=%v", ok, err)
	}
}

func TestPostgresEventQueueDequeueDoesNotDoubleClaim(t *testing.T) {
	ctx := context.Background()
	q := newPostgresEventQueue(t)

	id := uuid.NewString()
	if err := q.Enqueue(ctx, webhook.DeliveryJob{ID: id, NextAttemptAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if _, ok, err := q.Dequeue(ctx); err != nil || !ok {
		t.Fatalf("first Dequeue: ok=%v err=%v", ok, err)
	}
	job, ok, err := q.Dequeue(ctx)
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if ok && job.ID == id {
		t.Fatalf("expected job %q to already be claimed, got it again", id)
	}
}

func TestPostgresEventQueueFailReschedules(t *testing.T) {
	ctx := context.Background()
	q := newPostgresEventQueue(t)

	id := uuid.NewString()
	if err := q.Enqueue(ctx, webhook.DeliveryJob{ID: id, NextAttemptAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, ok, err := q.Dequeue(ctx); err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}

	if err := q.Fail(ctx, id, errors.New("connection refused"), time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	got, ok, err := q.Dequeue(ctx)
	if err != nil || !ok || got.ID != id {
		t.Fatalf("expected job re-claimable after Fail: ok=%v err=%v got=%+v", ok, err, got)
	}
	if got.Attempts != 1 || got.LastError != "connection refused" {
		t.Fatalf("unexpected job state after Fail: %+v", got)
	}
}
