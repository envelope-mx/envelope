package platform_test

import (
	"context"
	"testing"
	"time"

	"github.com/envelope-mx/envelope/internal/platform"
)

func TestHeadlessAppShutdownWaitsForLoopToReturn(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})

	a := &platform.HeadlessApp{
		Loop: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil
		},
	}

	runErr := make(chan error, 1)
	go func() { runErr <- a.Run(nil) }()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("Loop never started")
	}

	select {
	case <-stopped:
		t.Fatal("Loop stopped before Shutdown was called")
	default:
	}

	if err := a.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	select {
	case <-stopped:
	default:
		t.Fatal("Shutdown returned before Loop observed cancellation")
	}
	if err := <-runErr; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}
