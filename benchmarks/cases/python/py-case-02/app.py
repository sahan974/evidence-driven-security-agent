from dataclasses import dataclass

from diagnostics import DiagnosticsService


@dataclass(frozen=True)
class HostLookupRequest:
    hostname: str


class DiagnosticsEndpoint:
    def __init__(self, service: DiagnosticsService) -> None:
        self._service = service

    def run_lookup(self, request: HostLookupRequest) -> str:
        return self._service.resolve(request.hostname)


def inspect_host(host: str) -> str:
    endpoint = DiagnosticsEndpoint(DiagnosticsService())
    return endpoint.run_lookup(HostLookupRequest(hostname=host))
