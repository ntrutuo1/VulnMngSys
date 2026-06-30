import json
import subprocess
import atexit


class PowerShellAdapter:
    _active_processes = set()

    def __init__(self):
        atexit.register(self.cleanup_processes)

    @classmethod
    def cleanup_processes(cls):
        for p in list(cls._active_processes):
            try:
                p.kill()
            except Exception:
                pass
        cls._active_processes.clear()

    def execute_cmd(self, script: str, timeout: int = 30) -> str:
        p = None
        try:
            p = subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._active_processes.add(p)
            stdout, stderr = p.communicate(timeout=timeout)
            if p.returncode:
                raise RuntimeError((stderr or stdout or "PowerShell failed").strip())
            return stdout.strip()
        except subprocess.TimeoutExpired:
            if p:
                p.kill()
                p.communicate()
            raise RuntimeError("PowerShell command timed out")
        finally:
            if p:
                self._active_processes.discard(p)

    def execute_json(self, script: str, fallback):
        output = self.execute_cmd(script)
        if not output:
            return fallback
        data = json.loads(output)
        return [data] if isinstance(data, dict) else data
