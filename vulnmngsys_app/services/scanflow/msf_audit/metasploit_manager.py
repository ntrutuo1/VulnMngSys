"""Install, start, and monitor a local Metasploit msfrpcd runtime."""
from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .msfrpc_runner import MsfRpcRunner
from vulnmngsys_app.services.scanflow.paths import project_root


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
        atexit.register(self.shutdown)

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
            "message": message
            if connected
            else (
                message
                if "Connected to" not in message and "Local msfrpcd started" in self._message
                else self._message
            ),
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
                self._message = "Metasploit msfrpcd was not found in the portable Tools folder."
                return
            self._start_msfrpcd(self._msfrpcd)
            self._message = "Local msfrpcd started. Waiting for RPC connection."
        except Exception as exc:
            self._message = str(exc)
        finally:
            with self._lock:
                self._starting = False
                self._installing = False

    def shutdown(self) -> None:
        proc = self._process
        if proc is None:
            return
        self._process = None
        if proc.poll() is not None:
            return
        try:
            if os.name == "nt" and proc.pid:
                result = subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0:
                    return
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _install_metasploit(self) -> None:
        tools_dir = _app_root() / "Tools" / "metasploit-framework"
        usb_roots = _find_usb_tools_roots()
        usb_info = (
            "\nUSB Tools folders detected: " + ", ".join(str(root) for root in usb_roots)
            if usb_roots
            else "\nNo USB removable drives with a Tools folder were detected."
        )
        raise FileNotFoundError(
            "Metasploit msfrpcd was not found.\n"
            f"Searched app location: {tools_dir}"
            f"{usb_info}\n"
            "Copy Metasploit Framework into the Tools folder on your USB drive."
        )

    def _find_msfrpcd(self) -> Path | None:
        env_path = os.getenv("VULNMNGSYS_MSF_RPCD")
        if env_path:
            candidate = Path(env_path)
            if candidate.exists():
                return candidate

        for candidate in _portable_msfrpcd_paths():
            if candidate.exists():
                return candidate

        if os.getenv("VULNMNGSYS_ALLOW_SYSTEM_MSF") == "1":
            for name in ("msfrpcd.bat", "msfrpcd.cmd", "msfrpcd.exe", "msfrpcd"):
                found = shutil.which(name)
                if found:
                    return Path(found)
        return None

    def _start_msfrpcd(self, executable: Path) -> None:
        if executable.parent.name.casefold() == "bin":
            cwd = executable.parent.parent
            rel_executable = Path("bin") / executable.name
        else:
            cwd = executable.parent
            rel_executable = Path(executable.name)

        command = [
            str(rel_executable),
            "-P",
            self.config.password,
            "-a",
            self.config.host,
            "-p",
            str(self.config.port),
            "-S",
        ]
        if executable.suffix.casefold() in {".bat", ".cmd"}:
            command = ["cmd.exe", "/c", *command]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
            cwd=str(cwd),
        )


def _app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return project_root()


def _find_usb_tools_roots() -> list[Path]:
    """Scan removable Windows drives for portable Tools folders."""
    if os.name != "nt":
        return []

    import ctypes

    DRIVE_REMOVABLE = 2
    results: list[Path] = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[union-attr]

    for i in range(26):
        if not (bitmask & (1 << i)):
            continue
        letter = chr(ord("A") + i)
        root = f"{letter}:\\"
        try:
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)  # type: ignore[union-attr]
        except Exception:
            continue
        if drive_type != DRIVE_REMOVABLE:
            continue

        for app_folder in ("VulnMngApp",):
            tools_dir = Path(root) / app_folder / "Tools"
            if tools_dir.is_dir():
                results.append(tools_dir)

        root_tools = Path(root) / "Tools"
        if root_tools.is_dir():
            results.append(root_tools)

    return results


def _portable_msfrpcd_paths() -> list[Path]:
    """Search in the app layout and portable USB Tools folders."""
    app_root = _app_root()
    roots = [
        app_root / "Tools" / "metasploit-framework",
        app_root / "Tools",
    ]
    for usb_tools in _find_usb_tools_roots():
        roots.append(usb_tools / "metasploit-framework")
        roots.append(usb_tools)
    names = ("msfrpcd.bat", "msfrpcd.cmd", "msfrpcd.exe", "msfrpcd")
    candidates: list[Path] = []
    
    # 1. Fast path: check known direct locations
    for root_value in roots:
        if not root_value:
            continue
        root = Path(root_value)
        if not root.exists():
            continue
        for name in names:
            candidate = root / name
            if candidate.exists():
                candidates.append(candidate)
        bin_dir = root / "bin"
        for name in names:
            candidate = bin_dir / name
            if candidate.exists():
                candidates.append(candidate)
                
    # 2. Slow path fallback: only rglob if no candidates were found at all
    if not candidates:
        for root_value in roots:
            if not root_value:
                continue
            root = Path(root_value)
            if not root.exists():
                continue
            for name in names:
                candidates.extend(root.rglob(name))
                
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
