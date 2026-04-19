from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path


def _is_windows_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_windows_admin() -> None:
    script = str(Path(sys.argv[0]).resolve())
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        f'"{script}" {params}'.strip(),
        None,
        1,
    )
    if result <= 32:
        raise RuntimeError("Failed to elevate privileges on Windows")


def _is_unix_root() -> bool:
    return os.geteuid() == 0


def _relaunch_unix_root() -> None:
    cmd = ["sudo", "-E", sys.executable, str(Path(sys.argv[0]).resolve()), *sys.argv[1:]]
    completed = subprocess.run(cmd, check=False)
    if completed.returncode != 0:
        raise RuntimeError("Failed to elevate privileges with sudo")


def ensure_privileged() -> None:
    if sys.platform.startswith("win"):
        if _is_windows_admin():
            return
        _relaunch_windows_admin()
        raise SystemExit(0)

    if _is_unix_root():
        return

    _relaunch_unix_root()
    raise SystemExit(0)
