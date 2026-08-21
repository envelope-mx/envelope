// Package app is the root Goose module for the `api` instance: the
// Phase 0 health check plus internal/api's vhost/mailbox management
// routes (Phase 3).
package app

import (
	"github.com/awesome-goose/goose/types"

	"github.com/isaiahiroko/envelope/internal/api"
)

type AppModule struct{}

func (m *AppModule) Imports() []types.Module {
	return []types.Module{
		ROUTES,
		&api.Module{},
	}
}

func (m *AppModule) Exports() []any {
	return []any{}
}

func (m *AppModule) Declarations() []any {
	return []any{
		&AppService{},
	}
}
