from __future__ import annotations

import unittest

from vulnmngsys_app.models.protocols import Rule
from vulnmngsys_app.adapters.checkers.registry_checker import RegistryChecker


class FakeCollector:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def get_registry_value(self, hive: str, key: str, value_name: str):
        self.calls.append((hive, key, value_name))
        return 1, "REG_DWORD"


class RegistryCheckerTests(unittest.TestCase):
    def test_hklm_registry_path_is_automatically_collected(self) -> None:
        checker = RegistryChecker()
        collector = FakeCollector()
        rule = Rule(
            id="2.3.10.2",
            title="Restrict anonymous SAM enumeration",
            service="Network",
            check_type="Registry_HKLM",
            expected=1,
            raw_spec={
                "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM",
                "expected": 1,
                "operator": "==",
            },
        )

        result = checker.check(rule, collector)

        self.assertEqual(collector.calls, [("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM")])
        self.assertEqual(result.verdict, "PASS")
        self.assertEqual(result.actual_value, 1)


if __name__ == "__main__":
    unittest.main()
