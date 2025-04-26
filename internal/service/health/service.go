package health

import (
	"context"

	"github.com/eclipse-xfsc/crypto-provider-service/gen/health"
)

type Service struct {
	ver string
}

func New(version string) *Service {
	return &Service{ver: version}
}

func (s *Service) Liveness(_ context.Context) (*health.HealthResponse, error) {
	return &health.HealthResponse{
		Service: "signer",
		Status:  "up",
		Version: s.ver,
	}, nil
}

func (s *Service) Readiness(_ context.Context) (*health.HealthResponse, error) {
	return &health.HealthResponse{
		Service: "signer",
		Status:  "up",
		Version: s.ver,
	}, nil
}
