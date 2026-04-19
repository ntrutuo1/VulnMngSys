from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _is_windows_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_windows_admin() -> None:
    params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])

    if getattr(sys, "frozen", False):
        executable = str(Path(sys.executable).resolve())
        launch_params = params
    else:
        script = str(Path(sys.argv[0]).resolve())
        executable = sys.executable
        launch_params = f'"{script}" {params}'.strip()

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        launch_params,
        None,
        1,
    )
    if result <= 32:
        raise RuntimeError("Failed to elevate privileges on Windows")


def _is_unix_root() -> bool:
    return os.geteuid() == 0


def _relaunch_unix_root() -> None:
    script = str(Path(sys.argv[0]).resolve())
    if os.environ.get("DISPLAY") and shutil.which("pkexec"):
        cmd = ["pkexec", sys.executable, script, *sys.argv[1:]]
    elif shutil.which("sudo"):
        cmd = ["sudo", "-E", sys.executable, script, *sys.argv[1:]]
    else:
        raise RuntimeError("Missing privilege escalation tool. Install sudo or pkexec.")

    completed = subprocess.run(cmd, check=False)
    if completed.returncode != 0:
        raise RuntimeError("Failed to elevate privileges on Unix host")


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
