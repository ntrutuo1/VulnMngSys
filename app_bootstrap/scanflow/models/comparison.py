from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .rule import RuleComparisonResult


@dataclass(slots=True, frozen=True)
class ComparisonSummary:
    total: int
    passed: int
    failed: int
    manual: int
    items: list[RuleComparisonResult]
    report_file: Path