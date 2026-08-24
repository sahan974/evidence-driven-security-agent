import subprocess
from pathlib import Path


def read_file(user_path: str) -> str:
    """Intentionally vulnerable benchmark: no containment check."""
    return Path(user_path).read_text(encoding="utf-8")


def run_command(user_value: str) -> str:
    """Safe benchmark: an argument vector prevents shell metacharacter injection."""
    completed = subprocess.run(
        ["printf", "%s", user_value],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout
