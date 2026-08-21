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

// AccountController manages accounts (FR-5.2's business/tenant unit that
// owns one or more vhosts) — a platform-level resource, so CreateAccount
// and ListAccounts are admin-only the same way VhostController.CreateVhost
// used to be before vhost creation became self-serve under an account.
type AccountController struct {
	dir       *directory.Service `inject:""`
	tokens    apiauth.Store      `inject:""`
	admin     *AdminToken        `inject:""`
	rateLimit *RateLimitPolicy   `inject:""`
	audit     audit.Store        `inject:""`
}

// CreateAccount is admin-gated (the platform operator creates an account
// for a new business) and auto-issues that account's first token in the
// same response, exactly once, the same way TokenController.CreateToken
// already returns a raw token exactly once — from here on, that token is
// what the business uses to self-serve manage its own vhosts.
func (c *AccountController) CreateAccount(dto *CreateAccountDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireAdmin(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP)
	if errOut != nil {
		return errOut
	}
	if dto.Name == "" {
		return output.BadRequest("name is required")
	}

	acct, err := c.dir.CreateAccount(ctx, dto.Name)
	if err != nil {
		return output.InternalServerError("failed to create account")
	}

	tok, raw, err := mintToken(ctx, c.tokens, acct.ID, "default")
	if err != nil {
		return output.InternalServerError("failed to create account's first token")
	}

	recordAudit(ctx, c.audit, ac, "account.create", acct.ID, dto.Name)
	recordAudit(ctx, c.audit, ac, "token.create", acct.ID, "default")
	return output.Created(newAccountWithTokenView(acct, tok, raw))
}

// ListAccounts returns a page of every account — admin only, the same
// reasoning VhostController.ListVhosts's doc gives: no account-scoped
// token could legitimately see every other tenant's account.
func (c *AccountController) ListAccounts(dto *ListAccountsDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireAdmin(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP); errOut != nil {
		return errOut
	}

	accounts, err := c.dir.ListAccounts(ctx, dto.Cursor, dto.Limit)
	if err != nil {
		return output.InternalServerError("failed to list accounts")
	}

	views := make([]accountView, len(accounts))
	for i, a := range accounts {
		views[i] = newAccountView(a)
	}

	nextCursor := ""
	limit := dto.Limit
	if limit <= 0 || limit > directory.MaxVhostPageSize {
		limit = directory.DefaultVhostPageSize
	}
	if len(accounts) == limit {
		nextCursor = accounts[len(accounts)-1].ID
	}
	return output.SuccessWithMeta("", views, map[string]any{"nextCursor": nextCursor})
}

func (c *AccountController) GetAccount(dto *GetAccountDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireAccountAccess(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.ID); errOut != nil {
		return errOut
	}

	acct, err := c.dir.GetAccount(ctx, dto.ID)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("account not found")
		}
		return output.InternalServerError("failed to fetch account")
	}
	return output.OK(newAccountView(acct))
}

// ListEntries exposes NFR-COMP-4's audit log at account granularity —
// closes a gap the account-scoping migration would otherwise introduce:
// token.create/revoke and account.create entries are recorded with an
// account ID as Target (not a vhost ID), and the vhost-nested
// AuditController.ListEntries can never surface them.
func (c *AccountController) ListEntries(dto *ListAccountAuditEntriesDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireAccountAccess(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.AccountID); errOut != nil {
		return errOut
	}

	entries, err := c.audit.ListPage(ctx, dto.AccountID, dto.Cursor, dto.Limit)
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
