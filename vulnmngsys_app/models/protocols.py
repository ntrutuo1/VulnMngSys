from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Rule:
    """A normalized Windows Server configuration rule."""

    id: str
    title: str
    service: str
    check_type: str
    expected: Any
    description: str = ""
    remediation: str = ""
    raw_spec: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleComparisonResult:
    """Result of checking one rule."""

    passed: bool
    verdict: str
    actual_value: Any
    expected_value: Any
    error_message: str | None = None


class SystemCollector(abc.ABC):
    """Collects Windows Server configuration data."""

    @abc.abstractmethod
    def get_registry_value(self, hive: str, key: str, value_name: str) -> tuple[Any, str]:
        pass

    @abc.abstractmethod
    def run_powershell(self, command: str, timeout: int = 60) -> str:
        pass

    @abc.abstractmethod
    def get_secedit_policy(self) -> dict[str, str]:
        pass

    @abc.abstractmethod
    def get_user_rights(self) -> dict[str, list[str]]:
        pass

    @abc.abstractmethod
    def get_audit_policy(self) -> dict[str, str]:
        pass


class RuleChecker(abc.ABC):
    """Evaluates rules it can handle."""

    @abc.abstractmethod
    def can_handle(self, rule: Rule) -> bool:
        pass

    @abc.abstractmethod
    def check(self, rule: Rule, collector: SystemCollector) -> RuleComparisonResult:
        pass
