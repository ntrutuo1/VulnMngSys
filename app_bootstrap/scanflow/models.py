from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True, frozen=True)
class ScanInventory:
    computer_name: str
    os_caption: str
    os_version: str
    is_server: bool
    profile_key: str
    detected_service_count: int
    detected_services: list[dict[str, Any]]


@dataclass(slots=True, frozen=True)
class ScanModeSelection:
    full_scan: bool
    cancelled: bool = False


@dataclass(slots=True, frozen=True)
class RuleComparisonResult:
    rule_id: str
    title: str
    passed: bool
    verdict: str
    expected: str
    actual: str
    status: str
    check_type: str
    source: str
    guidance: list[str] = field(default_factory=list)
    service_name: str = ""


@dataclass(slots=True, frozen=True)
class ScanExecutionOutput:
    rule_file: Path
    temp_json_file: Path


@dataclass(slots=True, frozen=True)
class ComparisonSummary:
    total: int
    passed: int
    failed: int
    manual: int
    items: list[RuleComparisonResult]
    report_file: Path
