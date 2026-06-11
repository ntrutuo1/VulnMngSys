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
    "trace method is disabled",
    "no shortnames found",
    "certificate appears valid",
    "no interesting files",
    "no directory listing",
    "robots.txt not found",
}

# Phrases indicating an actual finding
_POSITIVE_PHRASES = {
    "internal ip",
    "short name",
    "8.3",
    "tilde",
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

_NOISE_PHRASES = (
    "auxiliary module execution completed",
    "changing the ssl option's value may require changing rport",
)

_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}


def _output_lower(raw: str) -> str:
    return raw.lower()


def _matches_positive(output_lower: str) -> bool:
    return any(phrase in output_lower for phrase in _POSITIVE_PHRASES)


def _matches_negative(output_lower: str) -> bool:
    return any(phrase in output_lower for phrase in _NEGATIVE_PHRASES)


def _extract_evidence(raw_output: str, max_chars: int = 300) -> str:
    """Extract the most relevant lines from raw output as evidence."""
    lines = [line.strip() for line in raw_output.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    # Keep non-empty module output, not msfconsole banner/prompt noise.
    relevant = [
        line for line in lines
        if line
        and not line.lower().startswith(("msf", "meterpreter"))
        and not line.startswith("[*] Starting")
        and not line.startswith("[*] Scanned")
        and "metasploit" not in line.lower()
        and "rapid7" not in line.lower()
        and not any(noise in line.lower() for noise in _NOISE_PHRASES)
    ]
    evidence = " | ".join(relevant[:5])
    return evidence[:max_chars] if evidence else ""


def _plain_evidence(raw_output: str) -> str:
    return _extract_evidence(raw_output, max_chars=500)


def _evidence_or_default(raw_output: str, default: str) -> str:
    return _plain_evidence(raw_output) or default


def _parse_allowed_methods(raw_output: str) -> set[str]:
    methods: set[str] = set()
    for line in raw_output.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        upper = line.upper()
        if "ALLOW" not in upper and "METHOD" not in upper and "SUPPORTED" not in upper:
            continue
        for method in re.findall(r"\b[A-Z]{3,10}\b", upper):
            if method in _DANGEROUS_METHODS or method in {"GET", "HEAD", "POST", "OPTIONS"}:
                methods.add(method)
    return methods


def _analyze_http_options(raw_output: str) -> dict[str, Any] | None:
    methods = _parse_allowed_methods(raw_output)
    if not methods:
        return None
    dangerous = sorted(methods & _DANGEROUS_METHODS)
    if dangerous:
        return {
            "status": "WARNING",
            "evidence": f"Dangerous HTTP methods exposed: {', '.join(dangerous)}. Allowed methods observed: {', '.join(sorted(methods))}.",
            "remediation": "",
        }
    return {
        "status": "PASS",
        "evidence": f"Allowed HTTP methods observed: {', '.join(sorted(methods))}. No dangerous methods detected.",
        "remediation": "",
    }


def _analyze_trace(raw_output: str) -> dict[str, Any] | None:
    out_lower = _output_lower(raw_output)
    if "does not support trace" in out_lower or "trace method is disabled" in out_lower or "not vulnerable" in out_lower:
        return {"status": "PASS", "evidence": _evidence_or_default(raw_output, "TRACE method was not accepted by IIS."), "remediation": ""}
    if "trace" in out_lower and any(word in out_lower for word in ("enabled", "vulnerable", "allows", "accepted", "reflected")):
        return {"status": "WARNING", "evidence": _evidence_or_default(raw_output, "TRACE method appears enabled."), "remediation": ""}
    return None


def _analyze_webdav(raw_output: str) -> dict[str, Any] | None:
    out_lower = _output_lower(raw_output)
    if "no webdav" in out_lower or "webdav is not enabled" in out_lower or "not found" in out_lower:
        return {"status": "PASS", "evidence": _evidence_or_default(raw_output, "WebDAV was not detected on the IIS endpoint."), "remediation": ""}
    if "webdav" in out_lower or "sharepoint" in out_lower or "dav" in out_lower:
        return {"status": "WARNING", "evidence": _evidence_or_default(raw_output, "WebDAV support was detected."), "remediation": ""}
    return None


def _analyze_directory_listing(raw_output: str) -> dict[str, Any] | None:
    out_lower = _output_lower(raw_output)
    if "no directory listing" in out_lower or "not found" in out_lower or "403" in out_lower:
        return {"status": "PASS", "evidence": _evidence_or_default(raw_output, "Directory browsing was not exposed."), "remediation": ""}
    if "directory listing" in out_lower or "index of" in out_lower:
        return {"status": "FAIL", "evidence": _evidence_or_default(raw_output, "Directory listing content was exposed."), "remediation": ""}
    return None


def _analyze_shortname(raw_output: str) -> dict[str, Any] | None:
    out_lower = _output_lower(raw_output)
    if "no shortnames found" in out_lower or "not vulnerable" in out_lower:
        return {"status": "PASS", "evidence": _evidence_or_default(raw_output, "IIS 8.3 short-name enumeration was not detected."), "remediation": ""}
    if any(phrase in out_lower for phrase in ("short name", "shortname", "8.3", "tilde")):
        return {"status": "FAIL", "evidence": _evidence_or_default(raw_output, "IIS 8.3 short-name enumeration signal was detected."), "remediation": ""}
    return None


def _analyze_tls(raw_output: str) -> dict[str, Any] | None:
    out_lower = _output_lower(raw_output)
    weak_protocols = []
    for label, patterns in {
        "SSLv2": ("sslv2", "ssl 2"),
        "SSLv3": ("sslv3", "ssl 3"),
        "TLS 1.0": ("tlsv1 ", "tls 1.0", "tls1.0"),
        "TLS 1.1": ("tlsv1.1", "tls 1.1", "tls1.1"),
    }.items():
        if any(pattern in out_lower for pattern in patterns):
            weak_protocols.append(label)
    if weak_protocols:
        details = _plain_evidence(raw_output)
        return {
            "status": "WARNING",
            "evidence": f"Weak TLS protocol support observed: {', '.join(weak_protocols)}. {details}".strip(),
            "remediation": "",
        }
    if "server does not appear to support ssl/tls" in out_lower or "connection refused" in out_lower or "no response" in out_lower:
        return {"status": "ERROR", "evidence": _evidence_or_default(raw_output, "HTTPS/TLS endpoint did not respond on the scanned port."), "remediation": "Verify IIS HTTPS binding and target port."}
    if any(token in out_lower for token in ("tlsv1.2", "tlsv1.3", "tls 1.2", "tls 1.3")):
        return {"status": "PASS", "evidence": _evidence_or_default(raw_output, "TLS scan completed; no weak protocol support was detected."), "remediation": ""}
    return None


def _analyze_certificate(raw_output: str) -> dict[str, Any] | None:
    out_lower = _output_lower(raw_output)
    if any(phrase in out_lower for phrase in ("expired", "issuer mismatch", "self-signed", "not trusted")):
        return {"status": "FAIL", "evidence": _evidence_or_default(raw_output, "Certificate trust, issuer, or expiry issue detected."), "remediation": ""}
    if "certificate appears valid" in out_lower or "subject" in out_lower or "issuer" in out_lower:
        return {"status": "PASS", "evidence": _evidence_or_default(raw_output, "Certificate details were collected and no issue was detected."), "remediation": ""}
    return None


def _module_specific_analysis(module_def: dict[str, Any], raw_output: str) -> dict[str, Any] | None:
    module_id = str(module_def.get("id", "")).lower()
    module_path = str(module_def.get("module", "")).lower()
    if module_id == "iis_http_options" or module_path.endswith("/options"):
        return _analyze_http_options(raw_output)
    if module_id == "iis_trace_method" or module_path.endswith("/trace"):
        return _analyze_trace(raw_output)
    if module_id == "iis_webdav_scanner":
        return _analyze_webdav(raw_output)
    if module_id == "iis_directory_listing":
        return _analyze_directory_listing(raw_output)
    if module_id == "iis_shortname_scanner":
        return _analyze_shortname(raw_output)
    if module_id == "iis_tls_versions":
        return _analyze_tls(raw_output)
    if module_id == "iis_https_certificate":
        return _analyze_certificate(raw_output)
    return None


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
    if any(phrase in out_lower for phrase in ("error:", "failed to", "exploit failed", "no route", "failed to validate")):
        return {
            "status": "ERROR",
            "evidence": evidence or "Module execution error",
            "remediation": "Check module options and target connectivity",
        }

    module_specific = _module_specific_analysis(module_def, raw_output)
    if module_specific:
        if module_specific["status"] in {"WARNING", "FAIL"}:
            module_specific["remediation"] = module_specific.get("remediation") or _get_remediation(module_def)
        return module_specific

    positive_match = _matches_positive(out_lower)
    negative_match = _matches_negative(out_lower)

    # INFO category: always just collect info
    if risk in _INFO_RISK_KEYWORDS or category == "fingerprinting" or category == "content_discovery":
        return {
            "status": "INFO",
            "evidence": evidence or "Module completed but did not return a service banner.",
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
        "evidence": evidence or "No finding signal was returned by the module.",
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
