from dataclasses import dataclass

from document_service import DocumentService


@dataclass(frozen=True)
class DocumentRequest:
    name: str


class DocumentEndpoint:
    def __init__(self, service: DocumentService) -> None:
        self._service = service

    def get(self, request: DocumentRequest) -> str:
        return self._service.retrieve(request.name)


def load_document(name: str) -> str:
    endpoint = DocumentEndpoint(DocumentService())
    return endpoint.get(DocumentRequest(name=name))
