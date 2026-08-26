import subprocess

def inspect_host(host: str) -> str:
    return subprocess.check_output(f"nslookup {host}", shell=True, text=True)
