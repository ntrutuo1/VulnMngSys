from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True, frozen=True)
class RuleManifest:
    profile: str
    quick: str
    full: tuple[str, ...]
    legacy: tuple[str, ...] = field(default_factory=tuple)
    manifest_path: Path | None = None
    source_dir: Path | None = None


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
