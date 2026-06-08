from __future__ import annotations

import unittest

from application.scan_service import ScanService
from domain.protocols import RuleComparisonResult


class FakeCollector:
    pass


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


if __name__ == "__main__":
    unittest.main()
