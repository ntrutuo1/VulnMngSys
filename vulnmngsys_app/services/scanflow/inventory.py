from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .models import ScanInventory
from .paths import project_root


def load_windows_inventory() -> ScanInventory:
    """Nhận diện OS/profile/dịch vụ khi khởi động — gọi trực tiếp inventory script."""
    script_path = (
        project_root()
        / "scripts"
        / "json_scanners"
        / "Get-WindowsServerInventory.ps1"
    )
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
            "-AsJson",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "Unknown inventory error"
        raise RuntimeError(detail)

    payload = (completed.stdout or "").strip()
    if not payload:
        raise RuntimeError("Inventory command returned empty output.")

    raw = json.loads(payload)
    return ScanInventory(
        computer_name=str(raw.get("ComputerName") or ""),
        os_caption=str(raw.get("OsCaption") or "Unknown"),
        os_version=str(raw.get("OsVersion") or "Unknown"),
        build_number=str(raw.get("BuildNumber") or ""),
        product_type=str(raw.get("ProductType") or ""),
        is_server=bool(raw.get("IsServer")),
        profile_key=str(raw.get("ProfileKey") or ""),
    )
