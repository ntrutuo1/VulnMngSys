from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnmngsys_app.services.iis_audit import IISAuditOrchestrator, _module_default_datastore, cancelServiceScan, reconfigure, sanitizeServiceReport, scanService, scanServiceCVE
from vulnmngsys_app.services.scanflow.msf_audit.module_loader import load_cve_modules, load_profile_metadata


class IisAuditUseCaseTests(unittest.TestCase):
    def test_orchestrator_exposes_main_use_cases(self) -> None:
        orchestrator = IISAuditOrchestrator()

        for name in [
            "getOSInfo",
            "scanConfiguration",
            "backupandRollback",
            "reconfigure",
            "scanService",
            "scanServiceCVE",
            "generateIISReport",
            "generateConfigScanReport",
        ]:
            self.assertTrue(callable(getattr(orchestrator, name)))

    def test_focused_iis_profile_has_complete_execution_contracts(self) -> None:
        modules = load_cve_modules()
        cves = {cve for module in modules for cve in module["cve"]}

        self.assertEqual(
            cves,
            {"CVE-2025-53772", "CVE-2025-27473", "CVE-2025-59282", "CVE-2025-59287"},
        )
        self.assertEqual(len(modules), 4)
        for module in modules:
            self.assertTrue(module.get("safe_to_run"))
            self.assertTrue(module.get("execution"))
            self.assertIn("exploit_execution_allowed", module["execution"])
            self.assertTrue(module.get("applicability"))
            self.assertTrue(module.get("evidence_contract"))
            self.assertTrue(module.get("decision_policy"))
            if module.get("check_method") != "local_only":
                self.assertTrue(module.get("default_datastore"))
                self.assertIn("RHOSTS", module["default_datastore"])
                self.assertIn("LHOST", module["default_datastore"])

    def test_profile_metadata_exposes_schema_and_common_options(self) -> None:
        metadata = load_profile_metadata()

        self.assertEqual(metadata["profile_name"], "iis_critical_cve_2025_local_audit")
        self.assertEqual(metadata["schema_version"], "2026-06-13")
        self.assertTrue(metadata["common_http_options"])
        self.assertTrue(metadata["common_https_options"])
        self.assertTrue(metadata["common_local_options"])
        self.assertTrue(metadata["execution_defaults"])
        self.assertEqual(len(metadata["cves"]), 4)
        self.assertIn("evidence_contract", metadata["cves"][0])

    def test_reconfigure_apply_requires_confirmation(self) -> None:
        payload = reconfigure(
            report={"items": []},
            app_root=Path("."),
            selected_rule_ids=["A"],
            apply=True,
            confirmed=False,
        )

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "CONFIRMATION_REQUIRED")

    def test_reconfigure_apply_rejects_empty_selection(self) -> None:
        payload = reconfigure(
            report={"items": []},
            app_root=Path("."),
            selected_rule_ids=[],
            apply=True,
            confirmed=True,
        )

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "RECONFIGURE_PLAN_UNSAFE")

    def test_scan_service_cve_requires_msfrpc(self) -> None:
        module = {
            "id": "iis_http_sys_test",
            "display_id": "IIS-CVE-001",
            "check_method": "msfrpc_check",
            "cve": ["CVE-2099-0001"],
            "name": "HTTP.sys test",
            "severity": "HIGH",
            "local_check": {},
        }

        class FakeManager:
            config = type("Config", (), {"host": "127.0.0.1", "port": 55552, "password": "", "ssl": True})()

            def wait_until_connected(self):
                return False, "offline"

        with tempfile.TemporaryDirectory() as tmp:
            with patch("vulnmngsys_app.services.scanflow.msf_audit.report_writer.writable_reports_dir", return_value=Path(tmp)):
                with patch("vulnmngsys_app.services.iis_audit.load_cve_modules", return_value=[module]):
                    with patch("vulnmngsys_app.services.iis_audit.get_msf_manager", return_value=FakeManager()):
                        with patch(
                            "vulnmngsys_app.services.iis_audit.run_local_patch_check",
                            return_value={"status": "FAIL", "applicable": True, "patch_found": False, "evidence": "missing KB"},
                        ):
                                payload = scanServiceCVE(selected_cves=["CVE-2099-0001"])

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], "MSFRPC_UNAVAILABLE")

    def test_scan_service_checks_all_iis_warehouse_modules(self) -> None:
        module = {
            "fullname": "exploit/windows/http/iis_test",
            "module_type": "exploit",
            "name": "IIS test module",
            "cves": ["CVE-2099-0002"],
            "components": ["IIS_CORE"],
            "references": ["CVE-2099-0002"],
            "default_datastore": {"RPORT": 80, "SSL": False},
            "check_supported": True,
        }

        class FakeManager:
            config = type("Config", (), {"host": "127.0.0.1", "port": 55552, "password": "", "ssl": True})()

            def wait_until_connected(self):
                return True, "online"

        with tempfile.TemporaryDirectory() as tmp:
            with patch("vulnmngsys_app.services.scanflow.msf_audit.report_writer.writable_reports_dir", return_value=Path(tmp)):
                with patch("vulnmngsys_app.services.iis_audit._load_warehouse_service_modules", return_value=[module]):
                    with patch("vulnmngsys_app.services.iis_audit.get_msf_manager", return_value=FakeManager()):
                        with patch("vulnmngsys_app.services.iis_audit._run_safe_msf_check", return_value={"status": "PASS", "evidence": "checked", "port": 80, "ssl": False, "datastore": {"RHOSTS": "127.0.0.1", "RPORT": 80, "SSL": False}, "check_executed": True}):
                            payload = scanService(services=["iis"])

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["service"], "iis")
        self.assertEqual(payload["results"][0]["module"], "exploit/windows/http/iis_test")
        self.assertEqual(payload["results"][0]["serviceStatus"], "CHECKED")
        self.assertEqual(payload["results"][0]["msf_check_state"], "CHECK_EXECUTED")
        self.assertEqual(payload["results"][0]["module_options"]["RPORT"], 80)
        self.assertEqual(payload["results"][0]["evidence"], "checked")

    def test_scan_service_all_uses_entire_warehouse(self) -> None:
        modules = [
            {
                "fullname": "exploit/windows/http/iis_test",
                "module_type": "exploit",
                "name": "IIS test module",
                "cves": ["CVE-2099-0002"],
                "components": ["IIS_CORE"],
                "references": ["CVE-2099-0002"],
                "check_supported": False,
            },
            {
                "fullname": "exploit/windows/smb/smb_test",
                "module_type": "exploit",
                "name": "SMB test module",
                "cves": ["CVE-2099-0003"],
                "components": ["SMB"],
                "references": ["CVE-2099-0003"],
                "check_supported": False,
            },
            {
                "fullname": "exploit/linux/http/linux_test",
                "relative_path": "exploits/linux/http/linux_test.rb",
                "module_type": "exploit",
                "name": "Linux test module",
                "cves": ["CVE-2099-0004"],
                "components": ["IIS_CORE"],
                "references": ["CVE-2099-0004"],
                "check_supported": False,
            },
        ]

        class FakeManager:
            config = type("Config", (), {"host": "127.0.0.1", "port": 55552, "password": "", "ssl": True})()

            def wait_until_connected(self):
                return True, "online"

        with tempfile.TemporaryDirectory() as tmp:
            with patch("vulnmngsys_app.services.scanflow.msf_audit.report_writer.writable_reports_dir", return_value=Path(tmp)):
                with patch("vulnmngsys_app.services.iis_audit._load_warehouse_service_modules", return_value=modules):
                    with patch("vulnmngsys_app.services.iis_audit.get_msf_manager", return_value=FakeManager()):
                        with patch("vulnmngsys_app.services.iis_audit._run_safe_msf_check", return_value={"status": "ERROR", "evidence": "check not supported", "port": 445, "ssl": False, "datastore": {"RHOSTS": "127.0.0.1", "RPORT": 445, "SSL": False}, "check_executed": True}):
                            payload = scanService(services=["all"])

        self.assertEqual(payload["service"], "all")
        self.assertEqual(len(payload["results"]), 2)
        self.assertEqual(payload["results"][0]["msf_check_state"], "CHECK_EXECUTED")
        self.assertNotIn("exploit/linux/http/linux_test", {row["module"] for row in payload["results"]})

    def test_service_score_ignores_unknown_and_info_modules(self) -> None:
        module = {
            "fullname": "exploit/windows/http/iis_test",
            "module_type": "exploit",
            "name": "IIS test module",
            "cves": ["CVE-2099-0002"],
            "components": ["IIS_CORE"],
            "references": ["CVE-2099-0002"],
            "check_supported": True,
        }

        class FakeManager:
            config = type("Config", (), {"host": "127.0.0.1", "port": 55552, "password": "", "ssl": True})()

            def wait_until_connected(self):
                return True, "online"

        with tempfile.TemporaryDirectory() as tmp:
            with patch("vulnmngsys_app.services.scanflow.msf_audit.report_writer.writable_reports_dir", return_value=Path(tmp)):
                with patch("vulnmngsys_app.services.iis_audit._load_warehouse_service_modules", return_value=[module]):
                    with patch("vulnmngsys_app.services.iis_audit.get_msf_manager", return_value=FakeManager()):
                        with patch("vulnmngsys_app.services.iis_audit._run_safe_msf_check", return_value={"status": "INFO", "evidence": "not enough signal", "datastore": {"RHOSTS": "127.0.0.1"}, "check_executed": True}):
                            payload = scanService(services=["iis"])

        self.assertEqual(payload["score"], 100)
        self.assertEqual(payload["summary"]["info"], 1)

    def test_sanitize_service_report_filters_stale_linux_rows(self) -> None:
        payload = sanitizeServiceReport(
            {
                "results": [
                    {
                        "module": "exploit/windows/http/iis_test",
                        "status": "PASS",
                        "evidence": "Module selected by local warehouse.",
                        "local_check_result": {"status": "INFO", "evidence": "Local warehouse selected the module."},
                        "msf_results": [{"status": "PASS", "evidence": "MSF says safe", "datastore": {"RPORT": 80}}],
                    },
                    {"module": "exploit/linux/http/linux_test", "status": "FAIL"},
                    {"module": "exploit/unix/webapp/old_test", "status": "ERROR"},
                ]
            }
        )

        self.assertEqual([row["module"] for row in payload["results"]], ["exploit/windows/http/iis_test"])
        self.assertEqual(payload["results"][0]["evidence"], "MSF says safe")
        self.assertEqual(payload["score"], 100)

    def test_scan_service_can_stop_with_partial_results(self) -> None:
        modules = [
            {"fullname": "exploit/windows/http/one", "module_type": "exploit", "name": "One", "cves": ["CVE-2099-0001"], "components": ["IIS_CORE"], "check_supported": True},
            {"fullname": "exploit/windows/http/two", "module_type": "exploit", "name": "Two", "cves": ["CVE-2099-0002"], "components": ["IIS_CORE"], "check_supported": True},
        ]

        class FakeManager:
            config = type("Config", (), {"host": "127.0.0.1", "port": 55552, "password": "", "ssl": True})()

            def wait_until_connected(self):
                return True, "online"

        def fake_check(_module, _target, _runner=None):
            cancelServiceScan()
            return {"status": "PASS", "evidence": "checked", "datastore": {"RHOSTS": "127.0.0.1"}, "check_executed": True}

        with tempfile.TemporaryDirectory() as tmp:
            with patch("vulnmngsys_app.services.scanflow.msf_audit.report_writer.writable_reports_dir", return_value=Path(tmp)):
                with patch("vulnmngsys_app.services.iis_audit._load_warehouse_service_modules", return_value=modules):
                    with patch("vulnmngsys_app.services.iis_audit.get_msf_manager", return_value=FakeManager()):
                        with patch("vulnmngsys_app.services.iis_audit._run_safe_msf_check_timed", side_effect=fake_check):
                            payload = scanService(services=["iis"])

        self.assertEqual(payload["scanStatus"], "CANCELLED")
        self.assertEqual(payload["completedModules"], 1)
        self.assertEqual(payload["totalModules"], 2)
        self.assertEqual(len(payload["results"]), 1)

    def test_module_default_datastore_sets_lhost_from_rhost(self) -> None:
        datastore = _module_default_datastore({"components": ["IIS_CORE"]}, "127.0.0.1")

        self.assertEqual(datastore["RHOST"], "127.0.0.1")
        self.assertEqual(datastore["RHOSTS"], "127.0.0.1")
        self.assertEqual(datastore["LHOST"], "127.0.0.1")

    def test_result_analyzer_smb_signing(self) -> None:
        from vulnmngsys_app.services.scanflow.msf_audit.result_analyzer import analyze
        module_def = {
            "id": "smb_signing_not_required_detection",
            "cve": [],
            "local_check": {
                "patch_guidance": "Enforce SMB signing"
            }
        }
        res_fail = analyze(module_def, "signatures:optional")
        self.assertEqual(res_fail["status"], "FAIL")
        self.assertIn("SMB Signing is optional", res_fail["evidence"])
        
        res_pass = analyze(module_def, "signatures:required")
        self.assertEqual(res_pass["status"], "PASS")
        self.assertIn("SMB Signing is required", res_pass["evidence"])

        res_info = analyze(module_def, "signatures:unknown")
        self.assertEqual(res_info["status"], "INFO")


if __name__ == "__main__":
    unittest.main()
