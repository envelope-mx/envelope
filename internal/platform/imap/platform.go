package imap

import (
	"crypto/tls"
	"fmt"

	goimap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/awesome-goose/goose/types"

	"github.com/isaiahiroko/envelope/internal/platform"
)

// Platform is a custom Goose platform (TRD §2.1) booting a go-imap server
// (FR-7.x).
type Platform struct {
	cfg Config
}

// NewPlatform returns a Platform for cfg.
func NewPlatform(cfg Config) *Platform {
	return &Platform{cfg: cfg}
}

var _ types.Platform = (*Platform)(nil)

func (p *Platform) Type() types.PlatformType {
	return types.PlatformType("imap")
}

func (p *Platform) Name() string {
	return p.cfg.Name
}

// Boot wires the go-imap server (TRD §2.1) and binds its listener. Like
// smtp.Platform, dependencies come from Config rather than the container —
// see that package's Boot doc for why.
func (p *Platform) Boot(_ types.Container) (types.App, error) {
	cfg := p.cfg
	server := imapserver.New(&imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return &session{cfg: cfg, conn: c}, &imapserver.GreetingData{}, nil
		},
		Caps: goimap.CapSet{
			goimap.CapIMAP4rev2: struct{}{},
		},
		// The listener below is already TLS-wrapped (implicit TLS, FR-7.1):
		// STARTTLS would be redundant, so it stays disabled here.
		InsecureAuth: true,
	})

	if p.cfg.TLSConfig == nil {
		return nil, fmt.Errorf("imap: TLSConfig is required (FR-7.1: implicit TLS)")
	}
	ln, err := tls.Listen("tcp", p.cfg.Addr, p.cfg.TLSConfig)
	if err != nil {
		return nil, fmt.Errorf("imap: listen on %s: %w", p.cfg.Addr, err)
	}

	return &platform.App{Listener: ln, Server: server}, nil
}
