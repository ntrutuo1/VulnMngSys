"""Analyze raw Metasploit module output and assign PASS/FAIL/WARNING/INFO status."""
from __future__ import annotations

import re
from typing import Any


# Signals that are considered informational regardless of match
_INFO_RISK_KEYWORDS = {"banner_version_exposure", "sensitive_path_disclosure"}

# Signals that yield WARNING instead of FAIL
_WARNING_RISK_KEYWORDS = {
    "webdav_enabled",
    "dangerous_methods_enabled",
    "weak_tls_protocols_or_ciphers",
}

# Phrases in module output that indicate "nothing found / clean"
_NEGATIVE_PHRASES = {
    "no vulnerabilities found",
    "no webdav",
    "webdav is not enabled",
    "not vulnerable",
    "does not support trace",
    "no shortnames found",
    "certificate appears valid",
    "no interesting files",
    "no directory listing",
    "robots.txt not found",
    "connection refused",
    "no response",
}

# Phrases indicating an actual finding
_POSITIVE_PHRASES = {
    "internal ip",
    "short name",
    "8.3",
    "tilde",
    "trace",
    "webdav",
    "sharepoint",
    "put",
    "delete",
    "directory listing",
    "index of",
    "file found",
    "interesting file",
    "robots.txt",
    "disallow",
    "ssl",
    "tls",
    "sslv",
    "expired",
    "issuer mismatch",
    "self-signed",
    "weak cipher",
    "vulnerable",
    "found:",
    "uploaded",
}


def _output_lower(raw: str) -> str:
    return raw.lower()


def _matches_positive(output_lower: str) -> bool:
    return any(phrase in output_lower for phrase in _POSITIVE_PHRASES)


def _matches_negative(output_lower: str) -> bool:
    return any(phrase in output_lower for phrase in _NEGATIVE_PHRASES)


def _extract_evidence(raw_output: str, max_chars: int = 300) -> str:
    """Extract the most relevant lines from raw output as evidence."""
    lines = [line.strip() for line in raw_output.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    # Keep non-empty, non-header lines
    relevant = [
        line for line in lines
        if line
        and not line.startswith("msf")
        and not line.startswith("[*] Starting")
        and not line.startswith("[*] Scanned")
        and "Metasploit" not in line
    ]
    evidence = " | ".join(relevant[:5])
    return evidence[:max_chars] if evidence else ""


def analyze(module_def: dict[str, Any], raw_output: str) -> dict[str, Any]:
    """Determine scan status from module definition and raw console output.

    Returns:
        dict with keys: status, evidence, remediation
    """
    risk = str(module_def.get("risk", "")).lower()
    category = str(module_def.get("category", "")).lower()
    safe_to_run = module_def.get("safe_to_run", True)

    # SKIPPED — module was excluded (conditional not in active mode)
    if safe_to_run == "conditional":
        return {
            "status": "SKIPPED",
            "evidence": "Skipped: active test mode not enabled",
            "remediation": "",
        }

    if not raw_output.strip():
        return {
            "status": "ERROR",
            "evidence": "No output received from module",
            "remediation": "Verify msfrpc connection and module availability",
        }

    out_lower = _output_lower(raw_output)
    evidence = _extract_evidence(raw_output)

    # Error indicators in output
    if any(phrase in out_lower for phrase in ("error:", "failed to", "exploit failed", "no route")):
        return {
            "status": "ERROR",
            "evidence": evidence or "Module execution error",
            "remediation": "Check module options and target connectivity",
        }

    positive_match = _matches_positive(out_lower)
    negative_match = _matches_negative(out_lower)

    # INFO category: always just collect info
    if risk in _INFO_RISK_KEYWORDS or category == "fingerprinting" or category == "content_discovery":
        return {
            "status": "INFO",
            "evidence": evidence,
            "remediation": "Review collected information for further analysis",
        }

    if positive_match and not negative_match:
        # Determine severity
        if risk in _WARNING_RISK_KEYWORDS:
            return {
                "status": "WARNING",
                "evidence": evidence,
                "remediation": _get_remediation(module_def),
            }
        return {
            "status": "FAIL",
            "evidence": evidence,
            "remediation": _get_remediation(module_def),
        }

    # Clean / no finding
    return {
        "status": "PASS",
        "evidence": "",
        "remediation": "",
    }


def _get_remediation(module_def: dict[str, Any]) -> str:
    """Build a remediation hint from module metadata."""
    risk = module_def.get("risk", "")
    name = module_def.get("name", "")
    cves = module_def.get("cve", [])
    cve_text = ", ".join(cves) if cves else ""

    hints: dict[str, str] = {
        "information_disclosure": "Review IIS configuration to suppress internal IP / header disclosure.",
        "webdav_enabled": "Disable WebDAV in IIS Manager if not required.",
        "dangerous_methods_enabled": "Restrict HTTP methods in IIS to GET and POST only.",
        "directory_listing": "Disable Directory Browsing in IIS site settings.",
        "backup_config_log_file_disclosure": "Remove or restrict access to backup/config/log files in web root.",
        "unauthorized_write_delete": "Disable write permissions on IIS paths; disable WebDAV PUT/DELETE.",
        "weak_tls_protocols_or_ciphers": "Disable TLS 1.0/1.1 and weak cipher suites via IIS Crypto or Group Policy.",
        "expired_or_untrusted_certificate": "Renew or replace the SSL certificate; ensure issuer chain is trusted.",
    }

    base = hints.get(risk, f"Review {name} configuration for security hardening.")
    if cve_text:
        base += f" See: {cve_text}."
    return base
