from __future__ import annotations

import ctypes

from .models import ScanInventory, ScanModeSelection
from .facades.scan_view import get_scan_view

YES_ID = 6
NO_ID = 7
CANCEL_ID = 2


def show_message_box(text: str, title: str, style: int) -> int:
    return int(ctypes.windll.user32.MessageBoxW(0, text, title, style))


def ask_scan_mode(inventory: ScanInventory) -> ScanModeSelection:
    prompt = get_scan_view().build_scan_mode_prompt(inventory=inventory)

    result = show_message_box(prompt, "VulnMngSys - Scan Mode", 0x03 | 0x20 | 0x40000)
    if result == CANCEL_ID:
        return ScanModeSelection(full_scan=False, cancelled=True)
    return ScanModeSelection(full_scan=(result == NO_ID), cancelled=False)
