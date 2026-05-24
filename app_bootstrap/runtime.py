import os
import sys
from pathlib import Path


def detect_headless_linux() -> bool:
    return (not sys.platform.startswith("win")) and (not os.environ.get("DISPLAY"))


def detect_windows_server() -> bool:
    if not sys.platform.startswith("win"):
        return False
    try:
        version = sys.getwindowsversion()
        return getattr(version, "product_type", 1) != 1
    except Exception:
        return False


def should_use_legacy_ui(force_legacy_ui: bool) -> bool:
    # Use legacy UI if explicitly requested, or when running on Windows Server by default.
    if force_legacy_ui:
        return True
    try:
        if detect_windows_server():
            try:
                import tempfile

                p = Path(tempfile.gettempdir()) / "vulnmngsys_startup.log"
                with p.open("a", encoding="utf-8") as fh:
                    fh.write("should_use_legacy_ui: detected Windows Server; using legacy UI\n")
            except Exception:
                pass
            return True
    except Exception:
        pass
    return False
