from __future__ import annotations

import ctypes

from .models import ScanInventory, ScanModeSelection

YES_ID = 6
NO_ID = 7
CANCEL_ID = 2


def show_message_box(text: str, title: str, style: int) -> int:
    return int(ctypes.windll.user32.MessageBoxW(0, text, title, style))


def ask_scan_mode(inventory: ScanInventory) -> ScanModeSelection:
    service_names = [item.get("Name") or item.get("DisplayName") for item in inventory.detected_services]
    top_services = "\n".join(f"- {name}" for name in service_names[:8]) or "- No critical services detected"

    prompt = (
        "Windows Server environment confirmed.\n\n"
        f"OS: {inventory.os_caption}\n"
        f"Version: {inventory.os_version}\n"
        f"Profile: {inventory.profile_key}\n"
        f"Services: {inventory.detected_service_count}\n\n"
        "Detected services:\n"
        f"{top_services}\n\n"
        "Choose the scan mode:\n"
        "Yes = Quick scan\n"
        "No = Full scan\n"
        "Cancel = Do not scan"
    )

    result = show_message_box(prompt, "VulnMngSys - Scan Mode", 0x03 | 0x20 | 0x40000)
    if result == CANCEL_ID:
        return ScanModeSelection(full_scan=False, cancelled=True)
    return ScanModeSelection(full_scan=(result == NO_ID), cancelled=False)
