from process_runner import ProcessRunner


class DiagnosticsService:
    def __init__(self, runner: ProcessRunner | None = None) -> None:
        self._runner = runner or ProcessRunner()

    def resolve(self, host: str) -> str:
        normalized = host.strip()
        if not normalized:
            raise ValueError("a host is required")
        return self._runner.lookup(normalized)
