"""Analyze IIS critical CVE audit output from MSF and local checks."""
from __future__ import annotations

from typing import Any


_POSITIVE_PHRASES = {
    "authorizationcookie",
    "binaryformatter",
    "deserialization",
    "deserialized",
    "getcookie",
    "msdeploy.axd accessible",
    "resource exhaustion",
    "target is vulnerable",
    "the target appears to be vulnerable",
    "vulnerable",
}

_NEGATIVE_PHRASES = {
    "already patched",
    "does not appear to be vulnerable",
    "not exploitable",
    "not installed",
    "not vulnerable",
    "patch detected",
    "patched",
}

_CONNECTION_INFO_PHRASES = {
    "connection refused",
    "no response",
    "not found",
    "404",
    "server returned no response",
}

_ERROR_PHRASES = {
    "failed to load module",
    "failed to validate",
    "module not found",
    "no such module",
    "unknown command",
}


def analyze(
    module_def: dict[str, Any],
    raw_output: str,
    local_check_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Determine final CVE status from MSF output and PowerShell local check."""
    module_id = str(module_def.get("id", "")).lower()
    if module_id == "cve_2025_53772_webdeploy_rce":
        msf = _analyze_webdeploy_rce(raw_output)
    elif module_id == "cve_2025_27473_httpsys_dos":
        msf = _analyze_httpsys_dos(raw_output)
    elif module_id == "cve_2025_59282_com_race":
        msf = {"status": "INFO", "evidence": "No Metasploit module configured for this local-only CVE."}
    elif module_id == "cve_2025_59287_wsus_rce":
        msf = _analyze_wsus_rce(raw_output)
    else:
        msf = _analyze_generic_cve(raw_output)

    return _combine_msf_and_local(module_def, msf, local_check_result or {})


def _analyze_webdeploy_rce(raw_output: str) -> dict[str, str]:
    out = _output_lower(raw_output)
    if not out:
        return {"status": "INFO", "evidence": "MSF Web Deploy probe did not return output."}
    if _has_error(out):
        return {"status": "ERROR", "evidence": _evidence_or_default(raw_output, "MSF Web Deploy check failed.")}
    if any(phrase in out for phrase in ("msdeploy.axd accessible", "binaryformatter", "deserialization", "vulnerable")):
        return {
            "status": "FAIL",
            "evidence": _evidence_or_default(raw_output, "Web Deploy deserialization signal detected."),
        }
    if any(phrase in out for phrase in _NEGATIVE_PHRASES):
        return {
            "status": "PASS",
            "evidence": _evidence_or_default(raw_output, "MSF did not find a Web Deploy RCE signal."),
        }
    if any(phrase in out for phrase in _CONNECTION_INFO_PHRASES):
        return {
            "status": "INFO",
            "evidence": _evidence_or_default(raw_output, "Web Deploy endpoint did not respond on the scanned port."),
        }
    return {
        "status": "INFO",
        "evidence": _evidence_or_default(raw_output, "Web Deploy probe completed without a direct vulnerable signal."),
    }


def _analyze_httpsys_dos(raw_output: str) -> dict[str, str]:
    out = _output_lower(raw_output)
    if not out:
        return {"status": "INFO", "evidence": "MSF HTTP.sys probe did not return output."}
    if _has_error(out):
        return {"status": "ERROR", "evidence": _evidence_or_default(raw_output, "MSF HTTP.sys check failed.")}
    if any(phrase in out for phrase in ("resource exhaustion", "cwe-400", "target is vulnerable", "vulnerable")):
        return {
            "status": "FAIL",
            "evidence": _evidence_or_default(raw_output, "HTTP.sys resource exhaustion signal detected."),
        }
    if any(phrase in out for phrase in _NEGATIVE_PHRASES):
        return {
            "status": "PASS",
            "evidence": _evidence_or_default(raw_output, "MSF did not find an HTTP.sys DoS signal."),
        }
    return {"status": "INFO", "evidence": _evidence_or_default(raw_output, "HTTP.sys fingerprint probe completed.")}


def _analyze_wsus_rce(raw_output: str) -> dict[str, str]:
    out = _output_lower(raw_output)
    if not out:
        return {"status": "INFO", "evidence": "MSF WSUS check mode did not return output."}
    if _has_error(out):
        return {"status": "ERROR", "evidence": _evidence_or_default(raw_output, "MSF WSUS check mode failed.")}
    if any(
        phrase in out
        for phrase in ("getcookie", "authorizationcookie", "binaryformatter", "deserialization", "vulnerable")
    ):
        return {
            "status": "FAIL",
            "evidence": _evidence_or_default(raw_output, "WSUS deserialization RCE signal detected."),
        }
    if any(phrase in out for phrase in _NEGATIVE_PHRASES):
        return {
            "status": "PASS",
            "evidence": _evidence_or_default(raw_output, "MSF check mode did not find a WSUS RCE signal."),
        }
    if any(phrase in out for phrase in _CONNECTION_INFO_PHRASES):
        return {
            "status": "INFO",
            "evidence": _evidence_or_default(raw_output, "WSUS endpoint did not respond on the scanned port."),
        }
    return {
        "status": "INFO",
        "evidence": _evidence_or_default(raw_output, "WSUS check mode completed without a direct vulnerable signal."),
    }


def _analyze_generic_cve(raw_output: str) -> dict[str, str]:
    out = _output_lower(raw_output)
    if not out:
        return {"status": "INFO", "evidence": "No MSF output received."}
    if _has_error(out):
        return {"status": "ERROR", "evidence": _evidence_or_default(raw_output, "MSF check failed.")}
    if any(phrase in out for phrase in _POSITIVE_PHRASES):
        return {"status": "FAIL", "evidence": _evidence_or_default(raw_output, "Vulnerability signal detected.")}
    if any(phrase in out for phrase in _NEGATIVE_PHRASES):
        return {"status": "PASS", "evidence": _evidence_or_default(raw_output, "No vulnerable signal detected.")}
    return {"status": "INFO", "evidence": _evidence_or_default(raw_output, "MSF check completed.")}


def _combine_msf_and_local(
    module_def: dict[str, Any],
    msf: dict[str, str],
    local: dict[str, Any],
) -> dict[str, Any]:
    local_status = str(local.get("status") or "").upper()
    msf_status = str(msf.get("status") or "INFO").upper()
    evidence = _join_evidence(
        _prefix("Local", str(local.get("evidence") or "")),
        _prefix("MSF", str(msf.get("evidence") or "")),
    )

    if local_status == "FAIL":
        return {
            "status": "FAIL",
            "evidence": evidence or "Local patch check indicates the host is exposed.",
            "remediation": _get_remediation(module_def),
        }
    if msf_status == "FAIL":
        return {
            "status": "FAIL",
            "evidence": evidence or "Metasploit returned a vulnerable signal.",
            "remediation": _get_remediation(module_def),
        }
    if local_status == "WARNING" or (msf_status == "ERROR" and local_status == "PASS"):
        return {
            "status": "WARNING",
            "evidence": evidence or "Local check passed, but MSF verification was incomplete.",
            "remediation": _get_remediation(module_def),
        }
    if local_status == "ERROR":
        return {
            "status": "ERROR" if msf_status == "ERROR" else "WARNING",
            "evidence": evidence or "Local PowerShell check failed.",
            "remediation": "Rerun the audit with local administrator privileges and verify PowerShell is available.",
        }
    if msf_status == "ERROR":
        return {
            "status": "ERROR",
            "evidence": evidence or "MSF verification failed.",
            "remediation": "Verify the configured Metasploit module is installed and check mode options are valid.",
        }
    if local_status == "SKIPPED":
        return {
            "status": msf_status if msf_status in {"PASS", "WARNING", "INFO"} else "INFO",
            "evidence": evidence or "Local check was skipped.",
            "remediation": "" if msf_status == "PASS" else _get_remediation(module_def),
        }

    if local_status == "PASS":
        return {
            "status": "PASS",
            "evidence": evidence or "Local patch/service check passed.",
            "remediation": "",
        }

    return {
        "status": msf_status,
        "evidence": evidence or str(msf.get("evidence") or "CVE check completed."),
        "remediation": "" if msf_status in {"PASS", "INFO"} else _get_remediation(module_def),
    }


def _get_remediation(module_def: dict[str, Any]) -> str:
    cves = ", ".join(module_def.get("cve", []) or [])
    module_id = str(module_def.get("id", ""))
    local_check = module_def.get("local_check") or {}
    patch_guidance = str(local_check.get("patch_guidance") or "").strip()
    hints: dict[str, str] = {
        "cve_2025_53772_webdeploy_rce": "Patch or disable Web Deploy/WMSvc if it is not required.",
        "cve_2025_27473_httpsys_dos": (
            "Patch Windows Server HTTP.sys and restrict exposed IIS listeners to required networks."
        ),
        "cve_2025_59282_com_race": "Install the October 2025 or later Windows Server cumulative update.",
        "cve_2025_59287_wsus_rce": "Patch WSUS, verify Update Services role exposure, and restrict ports 8530/8531.",
    }
    base = patch_guidance or hints.get(
        module_id,
        "Install the vendor remediation and review the affected service configuration.",
    )
    return f"{base} See: {cves}." if cves else base


def _output_lower(raw: str) -> str:
    return (raw or "").lower()


def _has_error(output_lower: str) -> bool:
    return any(phrase in output_lower for phrase in _ERROR_PHRASES)


def _extract_evidence(raw_output: str, max_chars: int = 360) -> str:
    lines = [
        line.strip()
        for line in (raw_output or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]
    relevant = [
        line for line in lines
        if line
        and not line.lower().startswith(("msf", "meterpreter"))
        and "metasploit" not in line.lower()
        and "rapid7" not in line.lower()
        and "auxiliary module execution completed" not in line.lower()
    ]
    evidence = " | ".join(relevant[:5])
    return evidence[:max_chars] if evidence else ""


def _evidence_or_default(raw_output: str, default: str) -> str:
    return _extract_evidence(raw_output) or default


def _prefix(label: str, value: str) -> str:
    value = value.strip()
    return f"{label}: {value}" if value else ""


def _join_evidence(*parts: str) -> str:
    return " | ".join(part for part in parts if part)
