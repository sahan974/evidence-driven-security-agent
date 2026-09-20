from document_store import DocumentStore


class DocumentService:
    def __init__(self, store: DocumentStore | None = None) -> None:
        self._store = store or DocumentStore()

    def retrieve(self, requested_name: str) -> str:
        name = requested_name.strip()
        if not name:
            raise ValueError("a document name is required")
        return self._store.read_text(name)
