package queue_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/envelope-mx/envelope/internal/queue"
)

func TestEnqueueDequeueComplete(t *testing.T) {
	ctx := context.Background()
	b := queue.NewMemoryBackend()

	job := queue.Job{ID: "1", Vhost: "example.com", From: "a@example.com", To: "b@example.com"}
	if err := b.Enqueue(ctx, job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	got, ok, err := b.Dequeue(ctx)
	if err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}
	if got.ID != "1" {
		t.Fatalf("got job %+v", got)
	}

	if err := b.Complete(ctx, "1"); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if _, ok, err := b.Dequeue(ctx); err != nil || ok {
		t.Fatalf("expected empty queue after Complete, ok=%v err=%v", ok, err)
	}
}

func TestDequeueRespectsNextAttemptAt(t *testing.T) {
	ctx := context.Background()
	b := queue.NewMemoryBackend()

	future := queue.Job{ID: "future", NextAttemptAt: time.Now().Add(time.Hour)}
	due := queue.Job{ID: "due", NextAttemptAt: time.Now().Add(-time.Second)}

	if err := b.Enqueue(ctx, future); err != nil {
		t.Fatalf("Enqueue future: %v", err)
	}
	if err := b.Enqueue(ctx, due); err != nil {
		t.Fatalf("Enqueue due: %v", err)
	}

	got, ok, err := b.Dequeue(ctx)
	if err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}
	if got.ID != "due" {
		t.Fatalf("expected the due job, got %+v", got)
	}

	if _, ok, err := b.Dequeue(ctx); err != nil || ok {
		t.Fatalf("expected no further due jobs, ok=%v err=%v", ok, err)
	}
}

func TestDequeueDoesNotDoubleClaim(t *testing.T) {
	ctx := context.Background()
	b := queue.NewMemoryBackend()

	if err := b.Enqueue(ctx, queue.Job{ID: "1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if _, ok, err := b.Dequeue(ctx); err != nil || !ok {
		t.Fatalf("first Dequeue: ok=%v err=%v", ok, err)
	}
	if _, ok, err := b.Dequeue(ctx); err != nil || ok {
		t.Fatalf("second Dequeue should find no unclaimed job: ok=%v err=%v", ok, err)
	}
}

func TestFailReschedulesAndAllowsRedequeue(t *testing.T) {
	ctx := context.Background()
	b := queue.NewMemoryBackend()

	if err := b.Enqueue(ctx, queue.Job{ID: "1"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, ok, err := b.Dequeue(ctx); err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}

	if err := b.Fail(ctx, "1", errors.New("connection refused"), time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	got, ok, err := b.Dequeue(ctx)
	if err != nil || !ok {
		t.Fatalf("Dequeue after Fail: ok=%v err=%v", ok, err)
	}
	if got.Attempts != 1 || got.LastError != "connection refused" {
		t.Fatalf("unexpected job state after Fail: %+v", got)
	}
}

func TestCompleteUnknownJobErrors(t *testing.T) {
	b := queue.NewMemoryBackend()
	if err := b.Complete(context.Background(), "missing"); err == nil {
		t.Fatal("expected error completing an unknown job")
	}
}
