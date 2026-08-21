package smtp

import (
	"fmt"
	"net"
	"time"

	gosmtp "github.com/emersion/go-smtp"

	"github.com/awesome-goose/goose/types"

	"github.com/envelope-mx/envelope/internal/platform"
)

// defaultTimeout bounds how long the server waits for a peer between
// commands / after DATA, respectively (go-smtp has no built-in default).
const defaultTimeout = 30 * time.Second

// Platform is a custom Goose platform (TRD §2.1) booting a go-smtp server
// in either Config.Mode.
type Platform struct {
	cfg Config
}

// NewPlatform returns a Platform for cfg. cfg.Mode determines which
// go-smtp Backend (inbound or submission) it boots.
func NewPlatform(cfg Config) *Platform {
	return &Platform{cfg: cfg}
}

var _ types.Platform = (*Platform)(nil)

func (p *Platform) Type() types.PlatformType {
	return types.PlatformType(p.cfg.Mode.String())
}

func (p *Platform) Name() string {
	return p.cfg.Name
}

// Boot wires the go-smtp server (TRD §2.1) and binds its listener. The
// container argument is unused: Config already carries every dependency
// (Directory, Store, Queue) explicitly rather than resolving them from
// Goose's per-instance DI container — see TRD §2.1's "Multi-port exposure"
// note on why each Instance gets its own container.
func (p *Platform) Boot(_ types.Container) (types.App, error) {
	var backend gosmtp.Backend
	switch p.cfg.Mode {
	case ModeSubmission:
		backend = &submissionBackend{cfg: p.cfg}
	default:
		backend = &inboundBackend{cfg: p.cfg}
	}

	server := gosmtp.NewServer(backend)
	server.Addr = p.cfg.Addr
	server.Domain = p.cfg.Domain
	server.TLSConfig = p.cfg.TLSConfig
	server.AllowInsecureAuth = p.cfg.AllowInsecureAuth
	server.ReadTimeout = defaultTimeout
	server.WriteTimeout = defaultTimeout
	// Always set, never left at go-smtp's zero-value "unlimited": this is
	// the hard, server-wide ceiling FR-2.7's mid-transfer rejection relies
	// on (see inboundSession.Data's readBounded doc).
	server.MaxMessageBytes = p.cfg.MaxMessageBytes
	if server.MaxMessageBytes <= 0 {
		server.MaxMessageBytes = defaultMaxMessageBytes
	}

	ln, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("smtp: listen on %s: %w", p.cfg.Addr, err)
	}

	return &platform.App{Listener: ln, Server: server}, nil
}
