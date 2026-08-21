// Package platform holds the scaffolding shared by every custom Goose
// platform Envelope defines for its TCP-based roles (TRD §2.1):
// internal/platform/smtp and internal/platform/imap. Neither go-smtp's
// *smtp.Server nor go-imap's *imapserver.Server is HTTP-shaped, so neither
// fits a stock Goose platform; this package is the one place that adapts
// "a thing with Serve(net.Listener) and a way to stop" to Goose's
// types.App, so smtp and imap don't each reimplement the same Run/Shutdown
// plumbing.
package platform

import (
	"context"
	"net"
	"time"

	"github.com/awesome-goose/goose/types"
)

// Server is the shape both go-smtp's *smtp.Server and go-imap's
// *imapserver.Server implement: serve a pre-bound listener, and close it.
type Server interface {
	Serve(l net.Listener) error
	Close() error
}

// GracefulServer is satisfied by servers that can drain in-flight
// connections before closing (go-smtp's *smtp.Server has Shutdown(ctx);
// go-imap's *imapserver.Server does not, as of go-imap/v2 beta — App.Shutdown
// falls back to plain Close for those, so NFR-AV-4's graceful drain applies
// wherever the underlying library supports it).
type GracefulServer interface {
	Shutdown(ctx context.Context) error
}

// ShutdownTimeout bounds how long App.Shutdown waits for a GracefulServer's
// in-flight connections to finish before giving up (NFR-AV-4).
var ShutdownTimeout = 30 * time.Second

// App adapts a Server plus a pre-bound net.Listener to Goose's types.App.
// Boot does the listening (so it can return a bind error immediately);
// Run just starts accepting on the already-bound listener.
type App struct {
	Listener net.Listener
	Server   Server
}

// Run starts serving on the pre-bound Listener. fn is unused: SMTP/IMAP
// dispatch doesn't go through Goose's HTTP router (TRD §2.1). Both
// go-smtp and go-imap's Serve return nil when Serve exits because Shutdown
// or Close closed the listener, so a nil-vs-error return here already
// distinguishes a clean stop from a real failure.
func (a *App) Run(fn func(c types.Context) error) error {
	return a.Server.Serve(a.Listener)
}

// Shutdown stops accepting new connections and, for a GracefulServer,
// waits up to ShutdownTimeout for in-flight connections to finish
// (NFR-AV-4) before giving up.
func (a *App) Shutdown() error {
	if gs, ok := a.Server.(GracefulServer); ok {
		ctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		return gs.Shutdown(ctx)
	}
	return a.Server.Close()
}
