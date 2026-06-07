from __future__ import annotations

from pathlib import Path

from .json_rule_engine import write_merged_scan
from .models import ScanInventory


def _collect_rule_files(profile_key: str, full_scan: bool) -> list[Path]:
    _ = (profile_key, full_scan)
    return []


def run_scan_for_profile(
    profile_key: str,
    full_scan: bool,
    inventory: ScanInventory | None = None,
) -> Path:
    """Run the JSON rule engine and return the merged scan artifact."""
    app_root = Path(__file__).resolve().parents[2]
    report_temp_dir = app_root / "reports" / "temp"

    return write_merged_scan(
        profile_key=profile_key,
        full_scan=full_scan,
        output_dir=report_temp_dir,
    )
