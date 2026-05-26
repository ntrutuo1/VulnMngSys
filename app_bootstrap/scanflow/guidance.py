from __future__ import annotations

from typing import Any

from .evaluate import format_expected_display


def build_guidance(rule: dict[str, Any], source: str, expected: str) -> list[str]:
    lines: list[str] = []

    registry_path = str(rule.get("registry_path") or rule.get("registry") or rule.get("gp_path") or "").strip()
    if registry_path and not registry_path.upper().startswith(("HK", "HKEY_")):
        lines.append(f"Open the policy path: {registry_path}")

    if source:
        lines.append(f"Check the configuration source: {source}")

    display_expected = expected or format_expected_display(
        rule.get("expected"),
        str(rule.get("title") or ""),
    )
    if display_expected:
        lines.append(f"Expected value: {display_expected}")

    reason = str(rule.get("reason") or "").strip()
    if reason:
        lines.append(f"Reason: {reason}")

    title = str(rule.get("title") or "").strip()
    if title:
        lines.append(f"Rule: {title}")

    remediation = str(rule.get("remediation") or "").strip()
    if remediation:
        lines.append(f"Remediation: {remediation}")

    return lines
