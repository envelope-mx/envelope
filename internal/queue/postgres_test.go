package queue_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/dbtest"
	"github.com/isaiahiroko/envelope/internal/queue"
)

func newPostgresBackend(t *testing.T) *queue.PostgresBackend {
	t.Helper()
	db := dbtest.DB(t)
	if err := queue.MigratePostgres(db); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	dbtest.Truncate(t, db, "queue_jobs")
	return queue.NewPostgresBackend(db)
}

func TestPostgresEnqueueDequeueComplete(t *testing.T) {
	ctx := context.Background()
	b := newPostgresBackend(t)

	id := uuid.NewString()
	job := queue.Job{ID: id, Vhost: "example.test", From: "a@example.test", To: "b@example.test", NextAttemptAt: time.Now().Add(-time.Second)}
	if err := b.Enqueue(ctx, job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	got, ok, err := findJob(ctx, b, id)
	if err != nil || !ok {
		t.Fatalf("expected to find enqueued job: ok=%v err=%v", ok, err)
	}
	if got.Vhost != "example.test" {
		t.Fatalf("unexpected job: %+v", got)
	}

	if err := b.Complete(ctx, id); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, ok, err := findJob(ctx, b, id); err != nil || ok {
		t.Fatalf("expected job gone after Complete: ok=%v err=%v", ok, err)
	}
}

func TestPostgresDequeueDoesNotDoubleClaim(t *testing.T) {
	ctx := context.Background()
	b := newPostgresBackend(t)

	id := uuid.NewString()
	if err := b.Enqueue(ctx, queue.Job{ID: id, NextAttemptAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if _, ok, err := findJob(ctx, b, id); err != nil || !ok {
		t.Fatalf("first Dequeue: ok=%v err=%v", ok, err)
	}
	// findJob dequeues by scanning Dequeue's results, so a second direct
	// Dequeue call must not find the same (now-claimed) job again.
	job, ok, err := b.Dequeue(ctx)
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if ok && job.ID == id {
		t.Fatalf("expected job %q to already be claimed, got it again", id)
	}
}

func TestPostgresFailReschedules(t *testing.T) {
	ctx := context.Background()
	b := newPostgresBackend(t)

	id := uuid.NewString()
	if err := b.Enqueue(ctx, queue.Job{ID: id, NextAttemptAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, ok, err := findJob(ctx, b, id); err != nil || !ok {
		t.Fatalf("Dequeue: ok=%v err=%v", ok, err)
	}

	if err := b.Fail(ctx, id, errors.New("connection refused"), time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatalf("Fail: %v", err)
	}

	got, ok, err := findJob(ctx, b, id)
	if err != nil || !ok {
		t.Fatalf("expected job re-claimable after Fail: ok=%v err=%v", ok, err)
	}
	if got.Attempts != 1 || got.LastError != "connection refused" {
		t.Fatalf("unexpected job state after Fail: %+v", got)
	}
}

func TestPostgresQueueSurvivesNewConnection(t *testing.T) {
	// NFR-AV-2: a job enqueued through one connection must be visible
	// (and durably claimable) through a completely separate connection —
	// the closest a stateless-process/external-Postgres architecture gets
	// to "survives a process restart" (the durability guarantee comes
	// from Postgres, not from any in-process state).
	ctx := context.Background()
	db1 := dbtest.DB(t)
	if err := queue.MigratePostgres(db1); err != nil {
		t.Fatalf("MigratePostgres: %v", err)
	}
	dbtest.Truncate(t, db1, "queue_jobs")
	b1 := queue.NewPostgresBackend(db1)

	id := uuid.NewString()
	if err := b1.Enqueue(ctx, queue.Job{ID: id, Vhost: "example.test", NextAttemptAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	db2 := dbtest.DB(t) // a fresh connection, standing in for a restarted process
	b2 := queue.NewPostgresBackend(db2)

	got, ok, err := b2.Dequeue(ctx)
	if err != nil || !ok || got.ID != id {
		t.Fatalf("expected job to survive on a new connection: ok=%v err=%v got=%+v", ok, err, got)
	}
}

func findJob(ctx context.Context, b *queue.PostgresBackend, id string) (queue.Job, bool, error) {
	for {
		job, ok, err := b.Dequeue(ctx)
		if err != nil || !ok {
			return queue.Job{}, false, err
		}
		if job.ID == id {
			return job, true, nil
		}
	}
}
