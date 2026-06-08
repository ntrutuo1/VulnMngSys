from __future__ import annotations

from collections.abc import Callable

from domain.protocols import RuleChecker

from .auditpol_checker import AuditpolChecker
from .powershell_checker import PowerShellChecker
from .registry_checker import RegistryChecker
from .secedit_checker import SeceditChecker

CheckerFactory = Callable[[], RuleChecker]


class CheckerRegistry:
    """Factory registry for scan checker strategies."""

    def __init__(self) -> None:
        self._factories: list[CheckerFactory] = []

    def register(self, factory: CheckerFactory) -> None:
        self._factories.append(factory)

    def build(self) -> list[RuleChecker]:
        return [factory() for factory in self._factories]


def default_checker_registry() -> CheckerRegistry:
    registry = CheckerRegistry()
    registry.register(RegistryChecker)
    registry.register(SeceditChecker)
    registry.register(AuditpolChecker)
    registry.register(PowerShellChecker)
    return registry
