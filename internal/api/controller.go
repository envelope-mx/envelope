package api

import (
	"context"
	"errors"

	"github.com/awesome-goose/goose/io/output"
	"github.com/awesome-goose/goose/types"

	"github.com/isaiahiroko/envelope/internal/apiauth"
	"github.com/isaiahiroko/envelope/internal/audit"
	"github.com/isaiahiroko/envelope/internal/directory"
)

// VhostController is the vhost/mailbox management API (FR-1.1, FR-1.4,
// FR-5.1). It depends on *directory.Service directly rather than the
// directory.Directory interface: vhost/mailbox CRUD is Service-only
// surface, not part of the minimal read/auth contract
// internal/platform/smtp and internal/platform/imap need.
type VhostController struct {
	dir       *directory.Service `inject:""`
	tokens    apiauth.Store      `inject:""`
	admin     *AdminToken        `inject:""`
	rateLimit *RateLimitPolicy   `inject:""`
	audit     audit.Store        `inject:""`
}

// CreateVhost registers a new vhost under dto.AccountID — self-serve: an
// account's own token can create vhosts for itself with no admin
// involvement (an admin may still create one for any account, since
// requireAccountAccess's IsAdmin check passes for any accountID).
func (c *VhostController) CreateVhost(dto *CreateVhostDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireAccountAccess(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.AccountID)
	if errOut != nil {
		return errOut
	}
	if dto.Domain == "" {
		return output.BadRequest("domain is required")
	}
	if _, err := c.dir.GetAccount(ctx, dto.AccountID); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("account not found")
		}
		return output.InternalServerError("failed to verify account")
	}

	v, err := c.dir.CreateVhost(ctx, dto.AccountID, dto.Domain)
	if err != nil {
		return output.InternalServerError("failed to create vhost")
	}
	recordAudit(ctx, c.audit, ac, "vhost.create", v.ID, dto.Domain)
	return output.Created(newVhostView(v))
}

// ListVhosts returns a page of every tenant's vhosts — admin only, the
// same reasoning as CreateVhost: no single vhost-scoped token could
// legitimately see every other tenant's domain. Cursor-paginated
// (FR-5.4) via dto.Cursor/dto.Limit; see directory.Service.ListVhosts's
// doc for why this endpoint specifically needed it proven and fixed
// rather than left as a generic aspiration.
func (c *VhostController) ListVhosts(dto *ListVhostsDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireAdmin(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP); errOut != nil {
		return errOut
	}

	vhosts, err := c.dir.ListVhosts(ctx, dto.Cursor, dto.Limit)
	if err != nil {
		return output.InternalServerError("failed to list vhosts")
	}

	views := make([]vhostView, len(vhosts))
	for i, v := range vhosts {
		views[i] = newVhostView(v)
	}

	nextCursor := ""
	limit := dto.Limit
	if limit <= 0 || limit > directory.MaxVhostPageSize {
		limit = directory.DefaultVhostPageSize
	}
	if len(vhosts) == limit {
		nextCursor = vhosts[len(vhosts)-1].ID
	}
	return output.SuccessWithMeta("", views, map[string]any{"nextCursor": nextCursor})
}

func (c *VhostController) GetVhost(dto *GetVhostDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.ID); errOut != nil {
		return errOut
	}

	v, err := c.dir.GetVhost(ctx, dto.ID)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("vhost not found")
		}
		return output.InternalServerError("failed to fetch vhost")
	}
	return output.OK(newVhostView(v))
}

// DeactivateVhost stops a vhost from accepting inbound mail or new
// submission (FR-1.4). A vhost's own token may deactivate itself (a
// tenant switching itself off is a legitimate self-service action); only
// an admin token may act on a vhost other than its own — enforced the
// same way every other vhost-scoped endpoint is.
func (c *VhostController) DeactivateVhost(dto *DeactivateVhostDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.ID)
	if errOut != nil {
		return errOut
	}

	if err := c.dir.DeactivateVhost(ctx, dto.ID); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("vhost not found")
		}
		return output.InternalServerError("failed to deactivate vhost")
	}
	recordAudit(ctx, c.audit, ac, "vhost.deactivate", dto.ID, "")
	return output.Success("vhost deactivated", nil)
}

// UpdateVhostPolicy sets FR-1.2's per-vhost policy, including NFR-COMP-1's
// retention window. A vhost's own token may update its own policy
// (self-service, the same self-service reasoning DeactivateVhost's doc
// gives); only an admin token may act on a vhost other than its own.
func (c *VhostController) UpdateVhostPolicy(dto *UpdateVhostPolicyDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.ID)
	if errOut != nil {
		return errOut
	}

	err := c.dir.UpdateVhostPolicy(ctx, dto.ID, directory.VhostPolicy{
		MaxMessageBytes:         dto.MaxMessageBytes,
		DailyQuota:              dto.DailyQuota,
		SpamRejectThreshold:     dto.SpamRejectThreshold,
		SpamQuarantineThreshold: dto.SpamQuarantineThreshold,
		RetentionDays:           dto.RetentionDays,
	})
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("vhost not found")
		}
		return output.InternalServerError("failed to update vhost policy")
	}

	v, err := c.dir.GetVhost(ctx, dto.ID)
	if err != nil {
		return output.InternalServerError("failed to fetch updated vhost")
	}
	recordAudit(ctx, c.audit, ac, "vhost.policy.update", dto.ID, "")
	return output.Success("vhost policy updated", newVhostView(v))
}

func (c *VhostController) CreateMailbox(dto *CreateMailboxDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID)
	if errOut != nil {
		return errOut
	}
	if dto.LocalPart == "" || dto.Password == "" {
		return output.BadRequest("localPart and password are required")
	}

	if _, err := c.dir.GetVhost(ctx, dto.VhostID); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("vhost not found")
		}
		return output.InternalServerError("failed to verify vhost")
	}

	mb, err := c.dir.CreateMailbox(ctx, dto.VhostID, dto.LocalPart, dto.Password)
	if err != nil {
		return output.InternalServerError("failed to create mailbox")
	}
	recordAudit(ctx, c.audit, ac, "mailbox.create", dto.VhostID, dto.LocalPart)
	return output.Created(newMailboxView(mb))
}

// ListMailboxes is cursor-paginated (FR-5.4) via dto.Cursor/dto.Limit — see
// ListVhosts's doc for the pattern, and directory.Service.ListMailboxes's
// doc for why the underlying method this calls (ListMailboxesPage) is a
// sibling of, not a replacement for, the unbounded ListMailboxes internal
// callers (DataController.Export) still use.
func (c *VhostController) ListMailboxes(dto *ListMailboxesDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID); errOut != nil {
		return errOut
	}

	mailboxes, err := c.dir.ListMailboxesPage(ctx, dto.VhostID, dto.Cursor, dto.Limit)
	if err != nil {
		return output.InternalServerError("failed to list mailboxes")
	}

	views := make([]mailboxView, len(mailboxes))
	for i, m := range mailboxes {
		views[i] = newMailboxView(m)
	}

	nextCursor := ""
	limit := dto.Limit
	if limit <= 0 || limit > directory.MaxVhostPageSize {
		limit = directory.DefaultVhostPageSize
	}
	if len(mailboxes) == limit {
		nextCursor = mailboxes[len(mailboxes)-1].ID
	}
	return output.SuccessWithMeta("", views, map[string]any{"nextCursor": nextCursor})
}

func (c *VhostController) GetMailbox(dto *GetMailboxDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID); errOut != nil {
		return errOut
	}

	mb, err := c.dir.GetMailbox(ctx, dto.VhostID, dto.ID)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("mailbox not found")
		}
		return output.InternalServerError("failed to fetch mailbox")
	}
	return output.OK(newMailboxView(mb))
}

func (c *VhostController) DeleteMailbox(dto *DeleteMailboxDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireVhostAccountAccess(ctx, c.dir, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.VhostID)
	if errOut != nil {
		return errOut
	}

	if err := c.dir.DeleteMailbox(ctx, dto.VhostID, dto.ID); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("mailbox not found")
		}
		return output.InternalServerError("failed to delete mailbox")
	}
	recordAudit(ctx, c.audit, ac, "mailbox.delete", dto.VhostID, dto.ID)
	return output.Success("mailbox deleted", nil)
}
