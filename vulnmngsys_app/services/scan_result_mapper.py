from __future__ import annotations

from typing import Any, Protocol

from vulnmngsys_app.services.scanflow.guidance import build_guidance
from vulnmngsys_app.services.scanflow.rule_metadata import cis_reference, short_reason
from vulnmngsys_app.models.protocols import Rule, RuleComparisonResult


class ScanResultMapper(Protocol):
    def map(self, rule: Rule, result: RuleComparisonResult) -> dict[str, Any]:
        pass


class LegacyScanPayloadMapper:
    """Maps model scan results to the existing JSON report payload."""

    def __init__(self, profile_key: str = "") -> None:
        self.profile_key = profile_key

    def map(self, rule: Rule, result: RuleComparisonResult) -> dict[str, Any]:
        raw = rule.raw_spec or {}
        passed = result.verdict == "PASS"
        source = raw.get("registry_path") or raw.get("powershell_check") or ""
        guidance = [] if passed else build_guidance(raw, source=str(source), expected=result.expected_value)

        status = "Collected" if result.verdict in ("PASS", "FAIL") else result.verdict

        return {
            "hash_id": str(raw.get("hash_id", "")),
            "service": rule.service,
            "service_id": raw.get("service_id"),
            "id": rule.id,
            "title": rule.title,
            "check_type": rule.check_type,
            "registry_path": str(raw.get("registry_path", "")),
            "expected": rule.expected,
            "operator": str(raw.get("operator", "")),
            "powershell_check": str(raw.get("powershell_check", "")),
            "remediation": rule.remediation,
            "reason": short_reason(raw.get("reason")),
            "cis_reference": cis_reference(self.profile_key, rule.id),
            "actual": str(result.actual_value),
            "status": status,
            "source": source,
            "passed": passed,
            "verdict": result.verdict,
            "guidance": guidance,
        }
