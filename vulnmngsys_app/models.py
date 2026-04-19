from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class RuleCheck:
    code: str
    title: str
    severity: str
    weight: int
    config_file_key: str
    evaluator: Callable[[str], tuple[bool, str]]


@dataclass(frozen=True)
class ModuleDefinition:
    module_id: str
    os_family: str
    os_version: str
    service_type: str
    display_name: str
    rules_source_file: str
    config_paths: dict[str, list[str]]
    checks: list[RuleCheck]


@dataclass
class RuleResult:
    code: str
    title: str
    severity: str
    weight: int
    passed: bool
    reason: str


@dataclass
class ScanSummary:
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    total_weight: int = 0
    passed_weight: int = 0
    hardening_index: int = 0
    grade: str = "D"
    warnings: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    module: ModuleDefinition
    used_config_paths: dict[str, str]
    summary: ScanSummary
    results: list[RuleResult]
