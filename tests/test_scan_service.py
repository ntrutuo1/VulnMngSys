from __future__ import annotations

import unittest

from vulnmngsys_app.services.scan_service import ScanService
from vulnmngsys_app.services.scan_result_mapper import LegacyScanPayloadMapper
from vulnmngsys_app.models.protocols import Rule
from vulnmngsys_app.models.protocols import RuleComparisonResult
from vulnmngsys_app.adapters.checkers.checker_registry import default_checker_registry


class FakeCollector:
    pass


class PowerShellFirstCollector:
    def run_powershell(self, command: str):
        return "1"

    def get_registry_value(self, hive: str, key: str, value_name: str):
        raise AssertionError("Registry should not run before powershell_check")

    def get_secedit_policy(self):
        raise AssertionError("Secedit snapshot should not run before powershell_check")

    def get_user_rights(self):
        raise AssertionError("User rights snapshot should not run before powershell_check")

    def get_audit_policy(self):
        raise AssertionError("Auditpol snapshot should not run before powershell_check")


class FakeMapper:
    def map(self, rule, result):
        return {
            "id": rule.id,
            "verdict": result.verdict,
            "actual": result.actual_value,
            "error": result.error_message,
        }


class MatchingChecker:
    def __init__(self, result):
        self.result = result

    def can_handle(self, rule):
        return True

    def check(self, rule, collector):
        return self.result


class FailingChecker:
    def can_handle(self, rule):
        return True

    def check(self, rule, collector):
        raise RuntimeError("boom")


class ScanServiceTests(unittest.TestCase):
    def test_run_scan_uses_injected_mapper(self) -> None:
        service = ScanService(
            FakeCollector(),
            [MatchingChecker(RuleComparisonResult(True, "PASS", "1", "1"))],
            result_mapper=FakeMapper(),
        )

        payload = service.run_scan([{"id": "A", "title": "Rule A", "expected": "1"}])

        self.assertEqual(payload, [{"id": "A", "verdict": "PASS", "actual": "1", "error": None}])

    def test_run_scan_maps_checker_exception_to_error_result(self) -> None:
        service = ScanService(FakeCollector(), [FailingChecker()], result_mapper=FakeMapper())

        payload = service.run_scan([{"id": "A", "title": "Rule A", "expected": "1"}])

        self.assertEqual(payload[0]["verdict"], "ERROR")
        self.assertEqual(payload[0]["error"], "boom")

    def test_run_scan_maps_unhandled_rule_to_manual(self) -> None:
        service = ScanService(FakeCollector(), [], result_mapper=FakeMapper())

        payload = service.run_scan([{"id": "A", "title": "Rule A", "expected": "1"}])

        self.assertEqual(payload[0]["verdict"], "MANUAL")
        self.assertEqual(payload[0]["error"], "No available checker")

    def test_legacy_mapper_preserves_error_status(self) -> None:
        mapper = LegacyScanPayloadMapper()
        rule = Rule(
            id="A",
            title="Rule A",
            service="Network",
            check_type="Registry_HKLM",
            expected="1",
            raw_spec={"registry_path": r"HKLM\Software\Test:Value"},
        )

        payload = mapper.map(rule, RuleComparisonResult(False, "ERROR", None, "1", "boom"))

        self.assertEqual(payload["verdict"], "ERROR")
        self.assertEqual(payload["status"], "ERROR")

    def test_powershell_check_runs_before_registry_probe(self) -> None:
        service = ScanService(
            PowerShellFirstCollector(),
            default_checker_registry().build(),
            result_mapper=FakeMapper(),
        )

        payload = service.run_scan(
            [
                {
                    "id": "2.3.10.2",
                    "title": "Restrict anonymous SAM enumeration",
                    "service": "Network",
                    "check_type": "Registry_HKLM",
                    "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM",
                    "powershell_check": "(Get-ItemPropertyValue -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymousSAM')",
                    "expected": 1,
                }
            ]
        )

        self.assertEqual(payload[0]["verdict"], "PASS")
        self.assertEqual(payload[0]["actual"], "1")


if __name__ == "__main__":
    unittest.main()
