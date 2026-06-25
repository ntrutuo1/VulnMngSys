"""Calculate a 0-100 security score from focused IIS CVE audit results."""
from __future__ import annotations

from typing import Any


_FAIL_PENALTY_BY_SEVERITY: dict[str, int] = {
    "CRITICAL": 30,
    "HIGH": 20,
}

_STATUS_PENALTY: dict[str, int] = {
    "WARNING": 5,
    "ERROR": 8,
}

_LOCAL_STATUS_PENALTY: dict[str, int] = {
    "WARNING": 5,
    "ERROR": 8,
}


def calculate_score(results: list[dict[str, Any]]) -> int:
    """Return integer score 0-100."""
    penalty = 0
    for result in results:
        status = str(result.get("status", "")).upper()
        severity = str(result.get("severity", "")).upper()
        if status == "FAIL":
            penalty += _FAIL_PENALTY_BY_SEVERITY.get(severity, 15)
        else:
            penalty += _STATUS_PENALTY.get(status, 0)

        local_status = str((result.get("local_check_result") or {}).get("status", "")).upper()
        if status == "PASS":
            penalty += _LOCAL_STATUS_PENALTY.get(local_status, 0)

    return max(0, min(100, 100 - penalty))


def score_label(score: int) -> str:
    """Return human-readable label for a score."""
    if score >= 80:
        return "Good"
    if score >= 60:
        return "Moderate"
    if score >= 40:
        return "Poor"
    return "Critical"


def score_color(score: int) -> str:
    """Return semantic color string for UI badge."""
    if score >= 80:
        return "green"
    if score >= 60:
        return "orange"
    return "red"
