from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True, frozen=True)
class ScanInventory:
    computer_name: str
    os_caption: str
    os_version: str
    build_number: str
    product_type: str
    is_server: bool
    profile_key: str


@dataclass(slots=True, frozen=True)
class ScanModeSelection:
    full_scan: bool
    cancelled: bool = False


@dataclass(slots=True, frozen=True)
class ScanExecutionOutput:
    rule_file: Path
    temp_json_file: Path
