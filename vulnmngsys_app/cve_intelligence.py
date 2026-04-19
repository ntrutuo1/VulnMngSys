from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CveRule:
    cve_id: str
    title: str
    severity: str
    service_type: str
    min_version: str | None = None
    max_exclusive_version: str | None = None
    os_family: str | None = None
    os_version_prefix: str | None = None
    reference: str = ""


@dataclass(frozen=True)
class CveAssessment:
    cve_id: str
    title: str
    severity: str
    reason: str
    reference: str


SERVICE_CVE_RULES: list[CveRule] = [
    CveRule(
        cve_id="CVE-2021-41773",
        title="Apache HTTP Server Path Traversal and RCE",
        severity="critical",
        service_type="apache-http",
        min_version="2.4.49",
        max_exclusive_version="2.4.50",
        reference="https://httpd.apache.org/security/vulnerabilities_24.html",
    ),
    CveRule(
        cve_id="CVE-2021-42013",
        title="Apache HTTP Server Path Traversal and RCE bypass",
        severity="critical",
        service_type="apache-http",
        min_version="2.4.50",
        max_exclusive_version="2.4.51",
        reference="https://httpd.apache.org/security/vulnerabilities_24.html",
    ),
    CveRule(
        cve_id="CVE-2023-25690",
        title="Apache HTTP Server request smuggling",
        severity="high",
        service_type="apache-http",
        min_version="2.4.0",
        max_exclusive_version="2.4.56",
        reference="https://httpd.apache.org/security/vulnerabilities_24.html",
    ),
    CveRule(
        cve_id="CVE-2020-1938",
        title="Apache Tomcat Ghostcat (AJP file read/include)",
        severity="critical",
        service_type="apache-tomcat",
        min_version="7.0.0",
        max_exclusive_version="10.0.0",
        reference="https://tomcat.apache.org/security-9.html",
    ),
    CveRule(
        cve_id="CVE-2024-56337",
        title="Apache Tomcat partial PUT / path equivalence issue",
        severity="high",
        service_type="apache-tomcat",
        min_version="10.1.0",
        max_exclusive_version="10.1.34",
        reference="https://tomcat.apache.org/security-10.html",
    ),
    CveRule(
        cve_id="CVE-2024-6387",
        title="OpenSSH regreSSHion race condition in sshd",
        severity="critical",
        service_type="ssh",
        min_version="8.5",
        max_exclusive_version="9.8",
        reference="https://www.openssh.com/security.html",
    ),
    CveRule(
        cve_id="CVE-2023-38408",
        title="OpenSSH agent remote code execution chain",
        severity="high",
        service_type="ssh",
        min_version="9.0",
        max_exclusive_version="9.3",
        reference="https://www.openssh.com/security.html",
    ),
]


COMBINATION_RULES: list[CveRule] = [
    CveRule(
        cve_id="CVE-2021-41773",
        title="Ubuntu 22.04 + Apache HTTP vulnerable branch requires patch verification",
        severity="high",
        service_type="apache-http",
        min_version="2.4.49",
        max_exclusive_version="2.4.51",
        os_family="linux",
        os_version_prefix="ubuntu-22.04",
        reference="https://ubuntu.com/security/notices",
    ),
    CveRule(
        cve_id="CVE-2024-6387",
        title="Ubuntu 22.04 OpenSSH packages need vendor backport confirmation",
        severity="high",
        service_type="ssh",
        min_version="8.5",
        max_exclusive_version="9.8",
        os_family="linux",
        os_version_prefix="ubuntu-22.04",
        reference="https://ubuntu.com/security/notices",
    ),
]


def _to_version_tuple(value: str) -> tuple[int, ...]:
    cleaned = []
    for chunk in value.replace("_", ".").split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        if digits == "":
            break
        cleaned.append(int(digits))
    return tuple(cleaned) if cleaned else (0,)


def _in_range(version: str, min_version: str | None, max_exclusive_version: str | None) -> bool:
    current = _to_version_tuple(version)
    if min_version is not None and current < _to_version_tuple(min_version):
        return False
    if max_exclusive_version is not None and current >= _to_version_tuple(max_exclusive_version):
        return False
    return True


def _match_rules(
    rules: Iterable[CveRule],
    *,
    os_family: str,
    os_version: str,
    service_type: str,
    service_version: str,
) -> list[CveAssessment]:
    results: list[CveAssessment] = []
    for rule in rules:
        if rule.service_type != service_type:
            continue
        if not _in_range(service_version, rule.min_version, rule.max_exclusive_version):
            continue
        if rule.os_family and rule.os_family != os_family:
            continue
        if rule.os_version_prefix and not os_version.startswith(rule.os_version_prefix):
            continue

        scope = f"{service_type} {service_version}"
        if rule.os_family:
            scope += f" on {os_family}/{os_version}"
        results.append(
            CveAssessment(
                cve_id=rule.cve_id,
                title=rule.title,
                severity=rule.severity,
                reason=f"Matched vulnerability rule for {scope}",
                reference=rule.reference,
            )
        )
    return results


def evaluate_cves(
    *,
    os_family: str,
    os_version: str,
    service_type: str,
    service_version: str | None,
) -> list[CveAssessment]:
    if not service_version:
        return []

    normalized_service_version = service_version.strip()
    if not normalized_service_version:
        return []

    assessments = _match_rules(
        SERVICE_CVE_RULES,
        os_family=os_family,
        os_version=os_version,
        service_type=service_type,
        service_version=normalized_service_version,
    )
    assessments.extend(
        _match_rules(
            COMBINATION_RULES,
            os_family=os_family,
            os_version=os_version,
            service_type=service_type,
            service_version=normalized_service_version,
        )
    )
    return assessments
