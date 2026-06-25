from __future__ import annotations

import os
import tempfile
from pathlib import Path


def app_root() -> Path:
    return Path(__file__).resolve().parents[3]


def project_root() -> Path:
    return app_root()


def writable_reports_dir(root: Path | None = None, *subdirs: str) -> Path:
    base_root = root or app_root()
    candidates = [
        base_root / "reports",
        _local_app_data_reports_dir(),
        Path(tempfile.gettempdir()) / "VulnMngSys" / "reports",
    ]

    for base in candidates:
        target = base.joinpath(*subdirs)
        if _can_write_dir(target):
            return target

    fallback = Path(tempfile.gettempdir()) / "VulnMngSys" / "reports"
    target = fallback.joinpath(*subdirs)
    target.mkdir(parents=True, exist_ok=True)
    return target


def _local_app_data_reports_dir() -> Path:
    local_app_data = os.getenv("LOCALAPPDATA")
    if local_app_data:
        return Path(local_app_data) / "VulnMngSys" / "reports"
    return Path.home() / "AppData" / "Local" / "VulnMngSys" / "reports"


def _can_write_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".vulnmngsys-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False
