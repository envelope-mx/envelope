package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/awesome-goose/goose/io/output"
	"github.com/awesome-goose/goose/types"

	"github.com/envelope-mx/envelope/internal/apiauth"
	"github.com/envelope-mx/envelope/internal/audit"
	"github.com/envelope-mx/envelope/internal/directory"
	"github.com/envelope-mx/envelope/internal/storage"
	"github.com/envelope-mx/envelope/internal/webhook"
)

// DataController implements NFR-COMP-2: data export/deletion on tenant
// request, available via the API — not solely via direct DB access, which
// was the only way to get at this before this controller existed.
type DataController struct {
	dir       *directory.Service `inject:""`
	store     storage.Store      `inject:""`
	webhooks  webhook.Store      `inject:""`
	tokens    apiauth.Store      `inject:""`
	admin     *AdminToken        `inject:""`
	audit     audit.Store        `inject:""`
	rateLimit *RateLimitPolicy   `inject:""`
}

// Export returns everything Envelope stores about a vhost: its policy
// (never its DKIM private key — vhostView already excludes that),
// mailboxes (never password hashes — mailboxView already excludes that),
// every stored message's metadata and full body (base64-encoded), webhook
// subscriptions (never secrets), and the audit log.
//
// Known limitation, stated plainly rather than silently accepted: this
// buffers every message body into one JSON response, the same way
// storage.Backend.Write already buffers a body into memory for a single
// write — reasonable for FR-4.4's "low/medium volume" GA target, not for
// an arbitrarily large mailbox. A streaming/paginated export would be the
// natural follow-up if a real tenant's volume makes this a problem, the
// same "don't fix a problem that hasn't been measured yet" judgment
// index/ENVELOPE.md's Phase 6 section already applied to the other list
// endpoints' pagination gap.
func (c *DataController) Export(dto *ExportVhostDataDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.ID)
	if errOut != nil {
		return errOut
	}

	v, err := c.dir.GetVhost(ctx, dto.ID)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("vhost not found")
		}
		return output.InternalServerError("failed to fetch vhost")
	}

	mailboxes, err := c.dir.ListMailboxes(ctx, dto.ID)
	if err != nil {
		return output.InternalServerError("failed to list mailboxes")
	}

	metas, err := c.store.ListVhost(ctx, v.Domain)
	if err != nil {
		return output.InternalServerError("failed to list messages")
	}
	messages := make([]messageExportView, 0, len(metas))
	for _, m := range metas {
		rc, err := c.store.Read(ctx, m.Ref)
		if err != nil {
			// A message that vanished between List and Read (e.g. a
			// concurrent retention purge) shouldn't fail the whole export
			// — best-effort, the same tolerance internal/retention.Purger
			// itself applies to its own per-message failures.
			continue
		}
		body, readErr := io.ReadAll(rc)
		rc.Close()
		if readErr != nil {
			continue
		}
		messages = append(messages, messageExportView{
			Mailbox: m.Ref.Mailbox, Size: m.Size, Flags: m.Flags, CreatedAt: m.CreatedAt,
			Body: base64.StdEncoding.EncodeToString(body),
		})
	}

	subs, err := c.webhooks.ListSubscriptions(ctx, v.Domain)
	if err != nil {
		return output.InternalServerError("failed to list webhook subscriptions")
	}

	entries, err := c.audit.List(ctx, dto.ID)
	if err != nil {
		return output.InternalServerError("failed to list audit log")
	}

	recordAudit(ctx, c.audit, ac, "vhost.data.export", dto.ID, "")
	return output.OK(newDataExportView(v, mailboxes, messages, dto.ID, subs, entries))
}

// Delete erases every stored message for a vhost (NFR-COMP-2's "deletion
// on tenant request") — message content, the actual personal data at
// stake. Deliberately narrower than deleting the vhost/mailbox records
// themselves: mailbox credentials remain (removing them is
// DeleteMailbox's job, one at a time, and there is no "delete this vhost
// entirely" operation in this codebase at all — DeactivateVhost only ever
// stops accepting mail, FR-1.4). Idempotent: erasing an already-empty
// vhost succeeds with messagesDeleted: 0, not an error.
func (c *DataController) Delete(dto *DeleteVhostDataDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.ID)
	if errOut != nil {
		return errOut
	}

	v, err := c.dir.GetVhost(ctx, dto.ID)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("vhost not found")
		}
		return output.InternalServerError("failed to fetch vhost")
	}

	metas, err := c.store.ListVhost(ctx, v.Domain)
	if err != nil {
		return output.InternalServerError("failed to list messages")
	}

	deleted := 0
	for _, m := range metas {
		if err := c.store.Delete(ctx, m.Ref); err != nil {
			continue
		}
		deleted++
	}

	recordAudit(ctx, c.audit, ac, "vhost.data.delete", dto.ID, fmt.Sprintf("%d messages", deleted))
	return output.Success("vhost data deleted", map[string]any{"messagesDeleted": deleted})
}
