package platform

import (
	"context"

	"github.com/awesome-goose/goose/types"
)

// HeadlessApp adapts a context-driven background loop (no net.Listener, no
// HTTP request cycle) to Goose's types.App — the shape TRD §4's "outbound
// queue... runs as a headless Goose instance" and "webhook dispatch"
// (bundled into the API role) actually need: internal/deliverer.Deliverer.Run
// and internal/webhook.Dispatcher.Run are both "drain a durable retry queue
// until told to stop" loops, not listeners. This gets them the same
// goose.Start(...) lifecycle (concurrent goroutine, centralized
// SIGINT/SIGTERM shutdown fan-out, NFR-AV-4 drain semantics) that
// platform.App already gives the TCP-based roles, without a second
// hand-rolled supervision path.
type HeadlessApp struct {
	// Loop is the background loop to execute. It must return promptly once
	// ctx is cancelled (NFR-AV-4: graceful shutdown must complete
	// in-progress work, not abandon it mid-attempt — Loop's own body is
	// responsible for that, e.g. finishing an in-flight delivery attempt
	// before observing cancellation).
	Loop func(ctx context.Context) error

	cancel context.CancelFunc
	done   chan struct{}
}

var _ types.App = (*HeadlessApp)(nil)

// Run starts Loop and blocks until it returns (either because Shutdown
// cancelled its context, or the loop stopped on its own). fn is unused,
// matching platform.App's own Run: neither TCP roles nor this headless
// case dispatch through Goose's HTTP router.
func (a *HeadlessApp) Run(fn func(c types.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.done = make(chan struct{})
	defer close(a.done)

	return a.Loop(ctx)
}

// Shutdown cancels Loop's context and waits for Run to return.
func (a *HeadlessApp) Shutdown() error {
	if a.cancel != nil {
		a.cancel()
	}
	if a.done != nil {
		<-a.done
	}
	return nil
}

// HeadlessPlatform adapts a background loop directly to Goose's
// types.Platform, for roles with no listener at all — internal/deliverer's
// Deliverer.Run and internal/webhook's Dispatcher.Run, the "outbound
// queue" and "webhook dispatch" roles TRD §4 describes as headless. This
// lets cmd/envelope/main.go register them as ordinary Instances alongside
// the TCP-based roles (same newInstance helper, same goose.Start(...)
// call) instead of hand-rolling a separate supervision path for
// background loops specifically.
type HeadlessPlatform struct {
	PlatformType types.PlatformType
	PlatformName string
	Loop         func(ctx context.Context) error
}

var _ types.Platform = (*HeadlessPlatform)(nil)

func (p *HeadlessPlatform) Type() types.PlatformType { return p.PlatformType }
func (p *HeadlessPlatform) Name() string             { return p.PlatformName }

// Boot ignores container for the same reason platform.App-based platforms
// do (see internal/platform/smtp's Boot doc): the loop's dependencies are
// already closed over by the caller that built it.
func (p *HeadlessPlatform) Boot(types.Container) (types.App, error) {
	return &HeadlessApp{Loop: p.Loop}, nil
}
