from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app_bootstrap.scanflow.remediation_logger import close_remediation_loggers, log_reconfig_event
from app_bootstrap.scanflow.service_verifier import ServiceStatus, verify_service_health, warnings_payload


class ServiceVerifierTests(unittest.TestCase):
    def test_verify_service_health_warns_when_running_service_stops(self) -> None:
        warnings = verify_service_health(
            before={"W3SVC": ServiceStatus(name="W3SVC", status="Running")},
            after={"W3SVC": ServiceStatus(name="W3SVC", status="Stopped")},
        )

        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings_payload(warnings)[0]["name"], "W3SVC")
        self.assertIn("Running to Stopped", warnings_payload(warnings)[0]["message"])

    def test_verify_service_health_ignores_previously_stopped_service(self) -> None:
        warnings = verify_service_health(
            before={"W3SVC": ServiceStatus(name="W3SVC", status="Stopped")},
            after={"W3SVC": ServiceStatus(name="W3SVC", status="Stopped")},
        )

        self.assertEqual(warnings, [])

    def test_log_reconfig_event_writes_remediation_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_reconfig_event(root, "test_event", {"ok": True})
            log_file = root / "reports" / "logs" / "remediation.log"

            self.assertTrue(log_file.exists())
            self.assertIn("test_event", log_file.read_text(encoding="utf-8"))
            close_remediation_loggers()


if __name__ == "__main__":
    unittest.main()
