package case02

type HostLookupRequest struct {
	Host string
}

type DiagnosticsEndpoint struct {
	service DiagnosticsService
}

func (endpoint DiagnosticsEndpoint) Inspect(request HostLookupRequest) ([]byte, error) {
	return endpoint.service.Resolve(request.Host)
}

func InspectHost(host string) ([]byte, error) {
	endpoint := DiagnosticsEndpoint{service: NewDiagnosticsService()}
	return endpoint.Inspect(HostLookupRequest{Host: host})
}
