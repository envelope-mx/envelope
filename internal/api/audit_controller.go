package api

import (
	"context"

	"github.com/awesome-goose/goose/io/output"
	"github.com/awesome-goose/goose/types"

	"github.com/isaiahiroko/envelope/internal/apiauth"
	"github.com/isaiahiroko/envelope/internal/audit"
	"github.com/isaiahiroko/envelope/internal/directory"
)

// AuditController exposes NFR-COMP-4's audit log for a vhost.
type AuditController struct {
	dir       *directory.Service `inject:""`
	tokens    apiauth.Store      `inject:""`
	admin     *AdminToken        `inject:""`
	rateLimit *RateLimitPolicy   `inject:""`
	audit     audit.Store        `inject:""`
}

// ListEntries is cursor-paginated (FR-5.4) via dto.Cursor/dto.Limit — see
// ListVhosts's doc for the pattern, and audit.Store.List's doc for why the
// underlying method this calls (ListPage) is a sibling of, not a
// replacement for, the unbounded List internal callers
// (DataController.Export) still use.
func (c *AuditController) ListEntries(dto *ListAuditEntriesDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID); errOut != nil {
		return errOut
	}

	entries, err := c.audit.ListPage(ctx, dto.VhostID, dto.Cursor, dto.Limit)
	if err != nil {
		return output.InternalServerError("failed to list audit log entries")
	}
	views := make([]auditEntryView, len(entries))
	for i, e := range entries {
		views[i] = newAuditEntryView(e)
	}

	nextCursor := ""
	limit := dto.Limit
	if limit <= 0 || limit > audit.MaxPageSize {
		limit = audit.DefaultPageSize
	}
	if len(entries) == limit {
		nextCursor = entries[len(entries)-1].ID
	}
	return output.SuccessWithMeta("", views, map[string]any{"nextCursor": nextCursor})
}
