from __future__ import annotations

import unittest

from vulnmngsys_app.services.scanflow.msf_audit.msfrpc_runner import _console_value


class MsfRpcRunnerTests(unittest.TestCase):
    def test_console_value_formats_bool_for_msfconsole(self) -> None:
        self.assertEqual(_console_value(False), "false")
        self.assertEqual(_console_value(True), "true")


if __name__ == "__main__":
    unittest.main()
