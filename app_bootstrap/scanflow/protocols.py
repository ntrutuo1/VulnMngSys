from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .models import RuleComparisonResult


@runtime_checkable
class SystemCollector(Protocol):
    def collect_snapshot(self) -> Any:
        ...

    def read_registry(self, path_spec: str) -> tuple[Any, str]:
        ...

    def run_command(self, command: str) -> str:
        ...


@runtime_checkable
class RuleChecker(Protocol):
    def can_handle(self, rule: dict[str, Any]) -> bool:
        ...

    def check(self, rule: dict[str, Any], snapshot: Any) -> RuleComparisonResult:
        ...


@runtime_checkable
class RemediationGenerator(Protocol):
    def can_handle(self, row: dict[str, Any]) -> bool:
        ...

    def generate(self, row: dict[str, Any]) -> list[str]:
        ...


@runtime_checkable
class ReportSerializer(Protocol):
    def serialize(self, results: list[RuleComparisonResult], output_path: Path) -> Path:
        ...


@runtime_checkable
class RuleRepository(Protocol):
    def load_rules(self, profile_key: str, full_scan: bool) -> list[dict[str, Any]]:
        ...

    def verify_integrity(self, profile_key: str) -> None:
        ...
