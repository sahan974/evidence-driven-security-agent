from invoice_store import InvoiceStore


class InvoiceService:
    def retrieve(self, invoices: dict[str, dict], invoice_id: str, user_id: str) -> dict:
        invoice = InvoiceStore(invoices).get(invoice_id.strip())
        if invoice["owner_id"] != user_id:
            raise PermissionError("not owner")
        return invoice
