import ctypes
import subprocess
import sys
import os
from pathlib import Path
from typing import Callable, Optional

from vulnmngsys_app.adapters.logging.system_logger import logger

def _is_windows() -> bool:
    return sys.platform.startswith("win")


def is_admin() -> bool:
    if not _is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:
        logger.warning(f"Failed to check admin status: {exc}")
        return False


def _show_elevation_prompt() -> bool:
    text = (
        "VulnMngSys can request Administrator permission to read full security settings.\n\n"
        "Choose Yes to restart as Administrator, or No to continue without elevation."
    )
    title = "VulnMngSys - Administrator Permission"
    # MB_YESNO (0x4) | MB_ICONQUESTION (0x20) | MB_TOPMOST (0x40000)
    result = ctypes.windll.user32.MessageBoxW(0, text, title, 0x4 | 0x20 | 0x40000)
    return result == 6


def _relaunch_as_admin() -> bool:
    params = subprocess.list2cmdline(sys.argv[1:]) if len(sys.argv) > 1 else ""
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        None,
        1,
    )
    return ret > 32


def ensure_admin_startup() -> None:
    if not _is_windows():
        raise RuntimeError("VulnMngSys supports Windows Server only.")

    if is_admin():
        logger.debug("ensure_admin_startup: on_windows=True is_admin=True")
        return

    # Allow forcing the elevation prompt via environment for diagnostics
    force_prompt = os.environ.get("VMS_FORCE_ELEVATION_PROMPT") == "1"

    if not _show_elevation_prompt() and not force_prompt:
        logger.info("User declined elevation prompt or prompt returned false; exiting.")
        raise SystemExit(0)

    if not _relaunch_as_admin():
        logger.error("Failed to relaunch as admin via ShellExecuteW")
        raise RuntimeError("Failed to relaunch process with Administrator permission.")

    logger.info("Relaunch requested; exiting current process to elevate.")
    raise SystemExit(0)


def run_legacy_privilege_guard(ensure_privileged_func: Optional[Callable[[], None]]) -> None:
    if ensure_privileged_func is None:
        return
    try:
        ensure_privileged_func()
    except RuntimeError as exc:
        logger.warning(f"Privilege escalation warning: {exc}")
        logger.warning("Continuing without elevation. Some config files may not be readable.")

