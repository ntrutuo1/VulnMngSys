"""Install, start, and monitor a local Metasploit msfrpcd runtime."""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .msfrpc_runner import MsfRpcRunner


@dataclass(frozen=True)
class MsfRpcConfig:
    host: str = "127.0.0.1"
    port: int = 55552
    password: str = ""
    ssl: bool = False


class MetasploitManager:
    def __init__(self) -> None:
        self.config = MsfRpcConfig(password=os.getenv("VULNMNGSYS_MSF_PASSWORD") or "vulnmngsys-msfrpc")
        self._lock = threading.Lock()
        self._starting = False
        self._installing = False
        self._message = "Not started"
        self._msfrpcd: Path | None = None
        self._process: subprocess.Popen[str] | None = None

    def ensure_async(self) -> None:
        with self._lock:
            if self._starting or self._installing:
                return
            self._starting = True
        threading.Thread(target=self._ensure_worker, name="vulnmngsys-msfrpc", daemon=True).start()

    def status(self) -> dict[str, Any]:
        connected, message = self.test_connection()
        executable = self._msfrpcd or self._find_msfrpcd()
        return {
            "ok": connected,
            "connected": connected,
            "starting": self._starting,
            "installing": self._installing,
            "message": message if connected else (message if "Connected to" not in message and "Local msfrpcd started" in self._message else self._message),
            "host": self.config.host,
            "port": self.config.port,
            "ssl": self.config.ssl,
            "runtime": "local",
            "executable": str(executable) if executable else "",
        }

    def wait_until_connected(self, timeout: float = 300.0) -> tuple[bool, str]:
        self.ensure_async()
        deadline = time.monotonic() + timeout
        last_message = self._message
        while time.monotonic() < deadline:
            connected, message = self.test_connection()
            if connected:
                return True, message
            last_message = self._message or message
            time.sleep(2.0)
        return False, last_message

    def test_connection(self) -> tuple[bool, str]:
        runner = MsfRpcRunner(
            host=self.config.host,
            port=self.config.port,
            password=self.config.password,
            ssl=self.config.ssl,
        )
        return runner.test_connection()

    def _ensure_worker(self) -> None:
        try:
            if self.test_connection()[0]:
                self._message = "Connected to existing local msfrpcd service."
                return
            self._msfrpcd = self._find_msfrpcd()
            if self._msfrpcd is None:
                self._install_metasploit()
                self._msfrpcd = self._find_msfrpcd()
            if self._msfrpcd is None:
                self._message = "Metasploit install finished, but msfrpcd was not found."
                return
            self._start_msfrpcd(self._msfrpcd)
            self._message = "Local msfrpcd started. Waiting for RPC connection."
        except Exception as exc:
            self._message = str(exc)
        finally:
            with self._lock:
                self._starting = False
                self._installing = False

    def _install_metasploit(self) -> None:
        script = Path(__file__).resolve().parents[3] / "scripts" / "install_metasploit.ps1"
        if not script.exists():
            raise FileNotFoundError(f"Installer script not found: {script}")
        self._installing = True
        self._message = "Metasploit not found. Installing Metasploit Framework in the background."
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Unknown installer error"
            raise RuntimeError(f"Metasploit installer failed: {detail}")

    def _find_msfrpcd(self) -> Path | None:
        env_path = os.getenv("VULNMNGSYS_MSF_RPCD")
        candidates = [Path(env_path)] if env_path else []
        for name in ("msfrpcd.bat", "msfrpcd.cmd", "msfrpcd.exe", "msfrpcd"):
            found = shutil.which(name)
            if found:
                candidates.append(Path(found))
        candidates.extend(_common_msfrpcd_paths())
        return next((path for path in candidates if path and path.exists()), None)

    def _start_msfrpcd(self, executable: Path) -> None:
        command = [str(executable), "-P", self.config.password, "-a", self.config.host, "-p", str(self.config.port), "-S"]
        if executable.suffix.casefold() in {".bat", ".cmd"}:
            command = ["cmd.exe", "/c", *command]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)


def _common_msfrpcd_paths() -> list[Path]:
    # Common locations where Metasploit may be installed on Windows.
    roots = [
        os.getenv("METASPLOIT_FRAMEWORK_HOME"),
        r"C:\Tools",
        r"C:\Tools\metasploit-framework",
        r"D:\metasploit-framework",
        r"C:\metasploit-framework",
        r"D:\metasploit-framework",
        r"C:\Program Files\Metasploit Framework",
        r"C:\Program Files (x86)\Metasploit Framework",
    ]
    names = ("msfrpcd.bat", "msfrpcd.cmd", "msfrpcd.exe", "msfrpcd")
    candidates: list[Path] = []
    for root_str in roots:
        if not root_str:
            continue
        root = Path(root_str)
        # Search directly in the root directory (some installers place the executable there).
        for name in names:
            candidate = root / name
            if candidate.exists():
                candidates.append(candidate)
        # Also search in the typical 'bin' subdirectory.
        bin_dir = root / "bin"
        for name in names:
            candidate = bin_dir / name
            if candidate.exists():
                candidates.append(candidate)
        # Fallback: recursively search for any matching executable under the root.
        for name in names:
            candidates.extend(root.rglob(name))
    # Deduplicate while preserving order.
    seen = set()
    unique_candidates = []
    for path in candidates:
        if path not in seen:
            seen.add(path)
            unique_candidates.append(path)
    return unique_candidates


_MANAGER = MetasploitManager()


def get_msf_manager() -> MetasploitManager:
    return _MANAGER
