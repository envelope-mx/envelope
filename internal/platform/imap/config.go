// Package imap is a custom Goose platform (TRD §2.1) wrapping go-imap for
// the IMAP role (FR-7.x).
package imap

import (
	"crypto/tls"

	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/storage"
)

// Config configures an imap Platform instance.
type Config struct {
	Name string
	Addr string // e.g. ":993"

	// TLSConfig is required: FR-7.1 requires IMAP4rev2 over *implicit*
	// TLS on 993, so the listener itself is TLS-wrapped (tls.Listen) —
	// unlike smtp.Config.TLSConfig, this is not a STARTTLS upgrade option.
	TLSConfig *tls.Config

	Directory directory.Directory
	Store     storage.Store
}
