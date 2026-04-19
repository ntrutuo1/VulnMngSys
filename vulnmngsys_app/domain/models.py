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
    explanation: str = ""


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
    check_metadata: dict[str, dict[str, str]] = field(default_factory=dict)


@dataclass
class RuleResult:
    code: str
    title: str
    severity: str
    weight: int
    passed: bool
    reason: str
    config_path: str = ""
    config_line: int = 0
    baseline: str = ""
    explanation: str = ""
    actual_line: str = ""
    suggested_line: str = ""


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
class CveAdvisory:
    cve_id: str
    title: str
    severity: str
    likelihood: str
    reason: str
    reference: str


@dataclass
class ScanReport:
    module: ModuleDefinition
    used_config_paths: dict[str, str]
    summary: ScanSummary
    results: list[RuleResult]
    version_context: dict[str, str] = field(default_factory=dict)
    cve_advisories: list[CveAdvisory] = field(default_factory=list)
