package app

import (
	"github.com/awesome-goose/goose/io/output"
	"github.com/awesome-goose/goose/types"
)

type AppController struct {
	appService *AppService `inject:""`
}

func (c *AppController) Health(_ *HealthRequest) types.Output {
	return output.JSON(map[string]any{
		"status": c.appService.Health(),
	})
}
