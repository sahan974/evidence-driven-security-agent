def read_invoice(invoices: dict[str, dict], invoice_id: str, user_id: str):
    invoice = invoices[invoice_id]
    if invoice["owner_id"] != user_id:
        raise PermissionError("not owner")
    return invoice
