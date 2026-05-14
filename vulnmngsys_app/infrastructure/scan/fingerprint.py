from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ...domain.models import CveAdvisory, MetasploitScanResult, ModuleDefinition, VulnerabilityFinding
from ..intel.cve_intelligence import evaluate_cves
from ..platform.metasploit import run_windows_service_scan


def _xampp_upgrade_warning(xampp_version: str | None) -> str:
    normalized = (xampp_version or "").strip()
    if normalized == "8.1.25":
        return "XAMPP 8.1.25 requires an upgrade. This version is flagged as outdated and should be updated to a newer supported release before deployment."
    return ""


def _scan_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _build_vulnerability_findings(
    module: ModuleDefinition,
    cve_matches: list[CveAdvisory],
    version_context: dict[str, str],
) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    service_version = version_context.get("service_version", "").strip()
    scope = module.service_type
    if service_version:
        scope = f"{scope} {service_version}"

    for match in cve_matches:
        findings.append(
            VulnerabilityFinding(
                identifier=match.cve_id,
                title=match.title,
                severity=match.severity,
                scope=scope,
                confidence=match.likelihood,
                evidence=match.reason,
                recommendation="Upgrade to a non-vulnerable version and validate the service configuration.",
                reference=match.reference,
            )
        )

    return findings


@dataclass(frozen=True, slots=True)
class FingerprintResult:
    scan_id: str
    version_context: dict[str, str]
    cve_advisories: list[CveAdvisory]
    vulnerability_findings: list[VulnerabilityFinding]
    metasploit_results: list[MetasploitScanResult]
    warnings: list[str]


class FingerprintEngine:
    def fingerprint(
        self,
        module: ModuleDefinition,
        os_version: str | None = None,
        service_version: str | None = None,
        xampp_version: str | None = None,
        target_host: str | None = None,
        enable_metasploit: bool = False,
    ) -> FingerprintResult:
        version_context = {
            "os_family": module.os_family,
            "os_version": os_version or module.os_version,
            "service_type": module.service_type,
            "service_version": service_version or "",
            "xampp_version": xampp_version or "",
            "target_host": target_host or "",
            "metasploit_enabled": "true" if enable_metasploit else "false",
        }

        cve_matches = evaluate_cves(
            os_family=module.os_family,
            os_version=version_context["os_version"],
            service_type=module.service_type,
            service_version=version_context["service_version"],
        )
        cve_advisories = [
            CveAdvisory(
                cve_id=item.cve_id,
                title=item.title,
                severity=item.severity,
                likelihood=item.likelihood,
                reason=item.reason,
                reference=item.reference,
            )
            for item in cve_matches
        ]
        vulnerability_findings = _build_vulnerability_findings(module, cve_advisories, version_context)

        warnings: list[str] = []
        xampp_warning = _xampp_upgrade_warning(xampp_version)
        if xampp_warning:
            warnings.append(xampp_warning)

        metasploit_results: list[MetasploitScanResult] = []
        if enable_metasploit and target_host and module.service_type == "windows-server":
            metasploit_results = run_windows_service_scan(target_host)

        return FingerprintResult(
            scan_id=_scan_id(),
            version_context=version_context,
            cve_advisories=cve_advisories,
            vulnerability_findings=vulnerability_findings,
            metasploit_results=metasploit_results,
            warnings=warnings,
        )