from pathlib import Path


class DocumentStore:
    def __init__(self, directory: Path | None = None) -> None:
        self._directory = directory or Path("documents")

    def read_text(self, name: str) -> str:
        candidate = self._directory / name
        return candidate.read_text(encoding="utf-8")
