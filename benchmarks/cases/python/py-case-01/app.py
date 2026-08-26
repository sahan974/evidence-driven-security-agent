from pathlib import Path

def load_document(name: str) -> str:
    return Path("documents", name).read_text(encoding="utf-8")
