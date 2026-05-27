from __future__ import annotations

from pathlib import Path

from .inventory import load_windows_inventory
from .json_rule_engine import write_merged_scan
from .models import ScanInventory


def _collect_rule_files(profile_key: str, full_scan: bool) -> list[Path]:
    _ = (profile_key, full_scan)
    return []


def _detected_service_names(inventory: ScanInventory | None = None) -> set[str]:
    selected_inventory = inventory
    if selected_inventory is None:
        try:
            selected_inventory = load_windows_inventory()
        except Exception:
            return set()

    names: set[str] = set()
    for item in selected_inventory.detected_services:
        service_name = str(item.get("Name") or "").strip()
        if service_name:
            names.add(service_name)
    return names


def run_scan_for_profile(
    profile_key: str,
    full_scan: bool,
    inventory: ScanInventory | None = None,
    selected_service_names: set[str] | None = None,
    selected_service_ids: set[int] | None = None,
) -> Path:
    """Run the JSON rule engine and return the merged scan artifact."""
    app_root = Path(__file__).resolve().parents[2]
    report_temp_dir = app_root / "reports" / "temp"

    normalized_selected_services = {
        str(name).strip()
        for name in (selected_service_names or set())
        if str(name).strip()
    }
    normalized_selected_service_ids: set[int] = set()
    for service_id in (selected_service_ids or set()):
        try:
            text = str(service_id).strip()
            if not text:
                continue
            normalized_selected_service_ids.add(int(text))
        except (TypeError, ValueError):
            continue
    detected_service_names = normalized_selected_services or _detected_service_names(inventory)

    return write_merged_scan(
        profile_key=profile_key,
        full_scan=full_scan,
        output_dir=report_temp_dir,
        detected_service_names=detected_service_names,
        detected_service_ids=normalized_selected_service_ids or None,
    )
