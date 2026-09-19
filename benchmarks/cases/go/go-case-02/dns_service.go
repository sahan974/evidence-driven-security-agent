package case02

import (
	"fmt"
	"strings"
)

type DiagnosticsService struct {
	runner ProcessRunner
}

func NewDiagnosticsService() DiagnosticsService {
	return DiagnosticsService{runner: ProcessRunner{}}
}

func (service DiagnosticsService) Resolve(requestedHost string) ([]byte, error) {
	host := strings.TrimSpace(requestedHost)
	if host == "" {
		return nil, fmt.Errorf("a host is required")
	}
	return service.runner.Lookup(host)
}
