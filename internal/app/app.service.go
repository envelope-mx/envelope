package app

type AppService struct{}

func (s *AppService) Health() string {
	return "ok"
}
