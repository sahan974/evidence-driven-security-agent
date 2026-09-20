class InvoiceStore:
    def __init__(self, invoices: dict[str, dict]) -> None:
        self._invoices = invoices

    def get(self, invoice_id: str) -> dict:
        return self._invoices[invoice_id]
