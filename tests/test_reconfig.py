from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vulnmngsys_app.services.scanflow.remediation_logger import close_remediation_loggers
from vulnmngsys_app.services.scanflow.reconfig import RemediationPipeline, generate_reconfig_script


class ReconfigTests(unittest.TestCase):
    def tearDown(self) -> None:
        close_remediation_loggers()

    def test_generate_reconfig_script_filters_selected_rules(self) -> None:
        report = {
            "items": [
                {
                    "id": "A",
                    "title": "Apply this",
                    "verdict": "FAIL",
                    "registry_path": "HKLM\\Software\\VulnMngSysTest:Enabled",
                    "expected": 1,
                },
                {
                    "id": "B",
                    "title": "Skip this",
                    "verdict": "FAIL",
                    "registry_path": "HKLM\\Software\\VulnMngSysTest:Skipped",
                    "expected": 1,
                },
            ]
        }

        with tempfile.TemporaryDirectory() as tmp:
            payload = generate_reconfig_script(report, Path(tmp), selected_rule_ids=["A"])
            script = Path(payload["scriptPath"]).read_text(encoding="utf-8")
            close_remediation_loggers()

        self.assertEqual(payload["selected"], 1)
        self.assertEqual(payload["applied"], 1)
        self.assertIn("scriptPath", payload)
        self.assertEqual(payload["registryBackupKeys"], ["HKLM\\Software\\VulnMngSysTest"])
        self.assertIn("Set-RegistryValue -Path 'HKLM:\\Software\\VulnMngSysTest'", script)
        self.assertIn("Apply this", script)
        self.assertNotIn("Skip this", script)

    def test_remediation_pipeline_apply_runs_backup_execute_and_verify(self) -> None:
        report = {
            "items": [
                {
                    "id": "A",
                    "title": "Apply this",
                    "verdict": "FAIL",
                    "registry_path": "HKLM\\Software\\VulnMngSysTest:Enabled",
                    "expected": 1,
                }
            ]
        }
        events: list[str] = []

        class FakeBackup:
            def trigger_backup(self, selected_rule_ids, registry_paths=None):
                events.append(f"backup:{selected_rule_ids}:{registry_paths}")
                return "backup-1"

            def rollback_config(self, backup_id):
                events.append(f"rollback:{backup_id}")
                return True

            def backup_path(self, backup_id):
                return Path("backup-root") / backup_id

        class FakeVerifier:
            def get_services_status(self):
                events.append("snapshot")
                return {"W3SVC": "Running"}

            def verify_after_fix(self, before_status):
                events.append(f"verify:{before_status['W3SVC']}")
                return True

        class FakeExecutor:
            def run(self, script_path):
                events.append(f"execute:{Path(script_path).name}")
                return SimpleNamespace(returncode=0, stdout="done", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            payload = RemediationPipeline(
                backup=FakeBackup(),
                verifier=FakeVerifier(),
                executor=FakeExecutor(),
            ).apply(report, Path(tmp), selected_rule_ids=["A"])
            close_remediation_loggers()

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["backupId"], "backup-1")
        self.assertEqual(payload["backupPath"], str(Path("backup-root") / "backup-1"))
        self.assertEqual(payload["registryBackupKeys"], ["HKLM\\Software\\VulnMngSysTest"])
        self.assertEqual(payload["stdout"], "done")
        self.assertEqual(events, ["backup:['A']:['HKLM\\\\Software\\\\VulnMngSysTest']", "snapshot", "execute:vulnmngsys_reconfig.ps1", "verify:Running"])

    def test_remediation_pipeline_rolls_back_when_verification_fails(self) -> None:
        report = {
            "items": [
                {
                    "id": "A",
                    "title": "Apply this",
                    "verdict": "FAIL",
                    "registry_path": "HKLM\\Software\\VulnMngSysTest:Enabled",
                    "expected": 1,
                }
            ]
        }
        events: list[str] = []

        class FakeBackup:
            def trigger_backup(self, selected_rule_ids, registry_paths=None):
                return "backup-2"

            def rollback_config(self, backup_id):
                events.append(f"rollback:{backup_id}")
                return True

            def backup_path(self, backup_id):
                return Path("backup-root") / backup_id

        class FakeVerifier:
            def get_services_status(self):
                return {"W3SVC": "Running"}

            def verify_after_fix(self, before_status):
                return False

        class FakeExecutor:
            def run(self, script_path):
                return SimpleNamespace(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            payload = RemediationPipeline(
                backup=FakeBackup(),
                verifier=FakeVerifier(),
                executor=FakeExecutor(),
            ).apply(report, Path(tmp), selected_rule_ids=["A"])
            close_remediation_loggers()

        self.assertFalse(payload["ok"])
        self.assertTrue(payload["autoRolledBack"])
        self.assertEqual(events, ["rollback:backup-2"])


if __name__ == "__main__":
    unittest.main()
