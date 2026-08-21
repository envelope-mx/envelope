package api

import "github.com/awesome-goose/goose/types"

// Module wires the vhost/mailbox/webhook/token/audit management API into
// the stock `api` Goose platform. *directory.Service, webhook.Store,
// apiauth.Store, audit.Store, and AdminToken must all be registered in
// the instance's container by an Initializer (see cmd/envelope/main.go)
// before this module is traversed, so every controller's inject:""
// fields resolve.
type Module struct{}

func (m *Module) Imports() []types.Module {
	return []types.Module{ROUTES}
}

func (m *Module) Exports() []any { return []any{} }

func (m *Module) Declarations() []any {
	return []any{
		&VhostController{}, &WebhookController{}, &TokenController{}, &AuditController{}, &DataController{},
		&AccountController{}, &MessageController{},
	}
}
