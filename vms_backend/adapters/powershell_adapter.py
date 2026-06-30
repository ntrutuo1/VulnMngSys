import json
import subprocess


class PowerShellAdapter:
    def execute_cmd(self, script: str, timeout: int = 30) -> str:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if completed.returncode:
            raise RuntimeError((completed.stderr or completed.stdout or "PowerShell failed").strip())
        return completed.stdout.strip()

    def execute_json(self, script: str, fallback):
        output = self.execute_cmd(script)
        if not output:
            return fallback
        data = json.loads(output)
        return [data] if isinstance(data, dict) else data
