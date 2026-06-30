import subprocess
import tempfile
from pathlib import Path

from ..config import METASPLOIT_FRAMEWORK_DIR, MSFCONSOLE_PATH


class MsfRpcAdapter:
    def execute_module(self, module: str, options: dict, timeout: int = 120):
        if not MSFCONSOLE_PATH.exists():
            return {"status": "skipped", "evidence": f"msfconsole not found: {MSFCONSOLE_PATH}"}
        commands = [f"use {module}"]
        for key, value in options.items():
            if value is None or value == "":
                continue
            commands.append(f"set {key} {value}")
        commands.extend(["run", "exit -y"])
        resource = self._write_resource(commands)
        try:
            completed = subprocess.run(
                [str(MSFCONSOLE_PATH), "-q", "-r", str(resource)],
                cwd=str(METASPLOIT_FRAMEWORK_DIR),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            return {"status": "completed" if completed.returncode == 0 else "failed", "evidence": output.strip()[-4000:]}
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "")
            return {"status": "timeout", "evidence": str(output)[-4000:]}
        finally:
            resource.unlink(missing_ok=True)

    def call_module(self, module: str, target: str):
        return self.execute_module(module, {"RHOSTS": target})

    def _write_resource(self, commands):
        handle = tempfile.NamedTemporaryFile("w", suffix=".rc", delete=False, encoding="utf-8")
        with handle:
            handle.write("\n".join(commands))
            handle.write("\n")
        return Path(handle.name)
