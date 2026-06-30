import subprocess
import tempfile
import atexit
from pathlib import Path

from ..config import METASPLOIT_FRAMEWORK_DIR, MSFCONSOLE_PATH


class MsfRpcAdapter:
    _active_processes = set()

    def __init__(self):
        # Register atexit handler to terminate all active subprocesses
        atexit.register(self.cleanup_processes)

    @classmethod
    def cleanup_processes(cls):
        for p in list(cls._active_processes):
            try:
                p.kill()
            except Exception:
                pass
        cls._active_processes.clear()

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
        
        p = None
        try:
            p = subprocess.Popen(
                [str(MSFCONSOLE_PATH), "-q", "-r", str(resource)],
                cwd=str(METASPLOIT_FRAMEWORK_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._active_processes.add(p)
            
            stdout, stderr = p.communicate(timeout=timeout)
            output = (stdout or "") + (stderr or "")
            cleaned = self._clean_output(output)
            return {"status": "completed" if p.returncode == 0 else "failed", "evidence": cleaned}
        except subprocess.TimeoutExpired:
            if p:
                p.kill()
                stdout, stderr = p.communicate()
                output = (stdout or "") + (stderr or "")
                cleaned = self._clean_output(output)
                return {"status": "timeout", "evidence": cleaned}
            return {"status": "timeout", "evidence": "Timeout expired."}
        except Exception as e:
            return {"status": "failed", "evidence": str(e)}
        finally:
            if p:
                self._active_processes.discard(p)
            resource.unlink(missing_ok=True)


    def call_module(self, module: str, target: str):
        return self.execute_module(module, {"RHOSTS": target})

    def _clean_output(self, output: str) -> str:
        if not output:
            return ""
        lines = output.splitlines()
        cleaned = []
        started = False
        for line in lines:
            if "> run" in line:
                started = True
                continue
            if "> exit -y" in line:
                started = False
                break
            if started:
                cleaned_line = line.strip()
                if not cleaned_line:
                    continue
                if cleaned_line.startswith("warning:") or "Win32API is deprecated" in line or "bundled_gems" in line:
                    continue
                cleaned.append(line)
        if not cleaned:
            for line in lines:
                cleaned_line = line.strip()
                if not cleaned_line:
                    continue
                if any(x in cleaned_line for x in ["Processing", "resource (", "exit -y", "warning:", "Win32API"]):
                    continue
                cleaned.append(line)
        return "\n".join(cleaned).strip()

    def _write_resource(self, commands):
        handle = tempfile.NamedTemporaryFile("w", suffix=".rc", delete=False, encoding="utf-8")
        with handle:
            handle.write("\n".join(commands))
            handle.write("\n")
        return Path(handle.name)

