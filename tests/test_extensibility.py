from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vulnmngsys_app.services.scanflow import scanner
from vulnmngsys_app.models.protocols import RuleComparisonResult
from vulnmngsys_app.adapters.checkers.checker_registry import CheckerRegistry, default_checker_registry


class FakeRepository:
    def load_rules(self, profile_key: str, full_scan: bool):
        return [{"id": profile_key, "title": "Rule", "expected": "ok", "check_type": "fake"}]


class FakeChecker:
    def can_handle(self, rule):
        return True

    def check(self, rule, collector):
        return RuleComparisonResult(True, "PASS", "ok", rule.expected)


class FakeCollector:
    pass


class ExtensibilityTests(unittest.TestCase):
    def test_default_checker_registry_builds_checker_instances(self) -> None:
        checkers = default_checker_registry().build()
        checker_names = {checker.__class__.__name__ for checker in checkers}

        self.assertEqual(checkers[0].__class__.__name__, "PowerShellChecker")
        self.assertIn("RegistryChecker", checker_names)
        self.assertIn("SeceditChecker", checker_names)
        self.assertIn("AuditpolChecker", checker_names)
        self.assertIn("PowerShellChecker", checker_names)

    def test_run_scan_for_profile_accepts_repository_and_checker_registry(self) -> None:
        registry = CheckerRegistry()
        registry.register(FakeChecker)
        with tempfile.TemporaryDirectory() as tmp:
            merged_path = scanner.run_scan_for_profile(
                "PROFILE",
                full_scan=False,
                rule_repository=FakeRepository(),
                collector=FakeCollector(),
                checkers=registry.build(),
                app_root=Path(tmp),
            )
            payload = json.loads(Path(merged_path).read_text(encoding="utf-8-sig"))

        self.assertEqual(payload[0]["id"], "PROFILE")
        self.assertEqual(payload[0]["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
