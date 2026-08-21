package api

import (
	"context"
	"errors"

	"github.com/awesome-goose/goose/io/output"
	"github.com/awesome-goose/goose/types"
	"github.com/google/uuid"

	"github.com/isaiahiroko/envelope/internal/apiauth"
	"github.com/isaiahiroko/envelope/internal/audit"
	"github.com/isaiahiroko/envelope/internal/directory"
)

// TokenController issues and revokes FR-5.2 API tokens scoped to an
// account. An account's own token can mint and revoke further tokens for
// itself (self-service rotation), or an admin can act on any account.
type TokenController struct {
	dir       *directory.Service `inject:""`
	tokens    apiauth.Store      `inject:""`
	admin     *AdminToken        `inject:""`
	rateLimit *RateLimitPolicy   `inject:""`
	audit     audit.Store        `inject:""`
}

// mintToken generates a fresh raw token and persists its hash under
// accountID — shared by TokenController.CreateToken and
// AccountController.CreateAccount (which mints an account's first token in
// the same response it creates the account in).
func mintToken(ctx context.Context, tokens apiauth.Store, accountID, label string) (apiauth.Token, string, error) {
	raw, hash, err := apiauth.GenerateToken()
	if err != nil {
		return apiauth.Token{}, "", err
	}
	tok, err := tokens.CreateToken(ctx, uuid.NewString(), accountID, label, hash)
	if err != nil {
		return apiauth.Token{}, "", err
	}
	return tok, raw, nil
}

// CreateToken mints a new account-scoped token and returns its raw value —
// the only time it's ever visible. Only TokenHash is persisted (see
// apiauth.HashToken's doc), so losing this response means the token is
// gone for good; the caller must revoke and mint a replacement.
func (c *TokenController) CreateToken(dto *CreateTokenDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireAccountAccess(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.AccountID)
	if errOut != nil {
		return errOut
	}
	if _, err := c.dir.GetAccount(ctx, dto.AccountID); err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			return output.NotFound("account not found")
		}
		return output.InternalServerError("failed to verify account")
	}

	tok, raw, err := mintToken(ctx, c.tokens, dto.AccountID, dto.Label)
	if err != nil {
		return output.InternalServerError("failed to create token")
	}
	recordAudit(ctx, c.audit, ac, "token.create", dto.AccountID, dto.Label)
	return output.Created(newTokenView(tok, raw))
}

// ListTokens is cursor-paginated (FR-5.4) via dto.Cursor/dto.Limit — see
// ListVhosts's doc for the pattern.
func (c *TokenController) ListTokens(dto *ListTokensDto) types.Output {
	ctx := context.Background()
	if _, errOut := requireAccountAccess(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.AccountID); errOut != nil {
		return errOut
	}

	tokens, err := c.tokens.ListTokensPage(ctx, dto.AccountID, dto.Cursor, dto.Limit)
	if err != nil {
		return output.InternalServerError("failed to list tokens")
	}
	views := make([]tokenView, len(tokens))
	for i, t := range tokens {
		views[i] = newTokenView(t, "")
	}

	nextCursor := ""
	limit := dto.Limit
	if limit <= 0 || limit > apiauth.MaxPageSize {
		limit = apiauth.DefaultPageSize
	}
	if len(tokens) == limit {
		nextCursor = tokens[len(tokens)-1].ID
	}
	return output.SuccessWithMeta("", views, map[string]any{"nextCursor": nextCursor})
}

func (c *TokenController) RevokeToken(dto *RevokeTokenDto) types.Output {
	ctx := context.Background()
	ac, errOut := requireAccountAccess(ctx, c.tokens, c.admin, c.rateLimit, dto.Authorization, dto.ClientIP, dto.AccountID)
	if errOut != nil {
		return errOut
	}

	if err := c.tokens.RevokeToken(ctx, dto.AccountID, dto.ID); err != nil {
		if errors.Is(err, apiauth.ErrNotFound) {
			return output.NotFound("token not found")
		}
		return output.InternalServerError("failed to revoke token")
	}
	recordAudit(ctx, c.audit, ac, "token.revoke", dto.AccountID, dto.ID)
	return output.Success("token revoked", nil)
}
