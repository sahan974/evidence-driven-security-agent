from dataclasses import dataclass

from invoice_service import InvoiceService


@dataclass(frozen=True)
class InvoiceRequest:
    invoice_id: str
    user_id: str


class InvoiceEndpoint:
    def __init__(self, service: InvoiceService) -> None:
        self._service = service

    def get(self, invoices: dict[str, dict], request: InvoiceRequest) -> dict:
        return self._service.retrieve(invoices, request.invoice_id, request.user_id)


def read_invoice(invoices: dict[str, dict], invoice_id: str, user_id: str):
    endpoint = InvoiceEndpoint(InvoiceService())
    return endpoint.get(invoices, InvoiceRequest(invoice_id, user_id))
