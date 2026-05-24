from __future__ import annotations

import ctypes

from .models import ScanInventory, ScanModeSelection

YES_ID = 6
NO_ID = 7
CANCEL_ID = 2


def show_message_box(text: str, title: str, style: int) -> int:
    return int(ctypes.windll.user32.MessageBoxW(0, text, title, style))


def ask_scan_mode(inventory: ScanInventory) -> ScanModeSelection:
    service_names = [item.get("DisplayName") or item.get("Name") for item in inventory.detected_services]
    top_services = "\n".join(f"- {name}" for name in service_names[:8]) or "- Không phát hiện dịch vụ trọng yếu"

    prompt = (
        "Đã xác nhận môi trường Windows Server.\n\n"
        f"OS: {inventory.os_caption}\n"
        f"Version: {inventory.os_version}\n"
        f"Profile: {inventory.profile_key}\n"
        f"Services: {inventory.detected_service_count}\n\n"
        "Một số dịch vụ chính:\n"
        f"{top_services}\n\n"
        "Chọn chế độ quét:\n"
        "Yes = Quét nhanh chuẩn nghiệp vụ\n"
        "No = Quét đầy đủ tất cả rule\n"
        "Cancel = Không quét"
    )

    result = show_message_box(prompt, "VulnMngSys - Chọn chế độ quét", 0x03 | 0x20 | 0x40000)
    if result == CANCEL_ID:
        return ScanModeSelection(full_scan=False, cancelled=True)
    return ScanModeSelection(full_scan=(result == NO_ID), cancelled=False)
