package app

import (
	"github.com/awesome-goose/goose/modules/router"
)

var ROUTES = router.ForRoutes(
	router.Get("/health", []any{&AppController{}, "Health"}),
)
