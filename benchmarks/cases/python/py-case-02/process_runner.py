import subprocess


class ProcessRunner:
    def lookup(self, host: str) -> str:
        command = f"nslookup {host}"
        return subprocess.check_output(command, shell=True, text=True)
