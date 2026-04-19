from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .models import ModuleDefinition, RuleResult, ScanReport, ScanSummary


class ModuleCatalog(Protocol):
    def list_modules(self) -> list[ModuleDefinition]:
        ...


class PathSelector(Protocol):
    def resolve(self, candidates: list[str]) -> str:
        ...


class ConfigReader(Protocol):
    def read_text(self, path: str) -> str:
        ...


class ScoringStrategy(Protocol):
    def summarize(self, results: list[RuleResult]) -> ScanSummary:
        ...


class ScanEngine(Protocol):
    def scan(
        self,
        module: ModuleDefinition,
        os_version: str | None = None,
        service_version: str | None = None,
    ) -> ScanReport:
        ...


class ReportWriter(Protocol):
    def write(self, report: ScanReport, output_dir: Path) -> Path:
        ...
