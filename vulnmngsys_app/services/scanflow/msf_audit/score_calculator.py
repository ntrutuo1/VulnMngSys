"""Calculate a 0-100 security score from focused IIS CVE audit results using DREAD model."""
from __future__ import annotations

from typing import Any


def calculate_dread_details(status: str, original_severity: str) -> dict[str, Any]:
    """Calculate DREAD details (D, R, E, A, D scores) and dread severity.
    
    If status is not FAIL/WARNING/LIKELY, the check is considered safe (Info).
    """
    status_upper = str(status or "").upper()
    sev_upper = str(original_severity or "").upper()
    
    # Non-vulnerable status maps to Info (score 0.0)
    if status_upper not in {"FAIL", "WARNING", "LIKELY"}:
        return {
            "damage": 0.0,
            "reproducibility": 0.0,
            "exploitability": 0.0,
            "affected_users": 0.0,
            "discoverability": 0.0,
            "score": 0.0,
            "severity": "info",
        }
        
    # Map original severity to DREAD components (D, R, E, A, D) on 0-10 scale
    if sev_upper == "CRITICAL":
        d, r, e, a, disc = 10.0, 9.0, 9.0, 9.0, 10.0
    elif sev_upper == "HIGH":
        d, r, e, a, disc = 8.0, 9.0, 8.0, 9.0, 10.0
    elif sev_upper == "MEDIUM":
        d, r, e, a, disc = 6.0, 8.0, 6.0, 8.0, 9.0
    else:  # LOW or WARNING
        d, r, e, a, disc = 2.0, 5.0, 4.0, 5.0, 6.0
        
    score = round((d + r + e + a + disc) / 5.0, 1)
    
    if score >= 8.0:
        severity = "high"
    elif score >= 5.0:
        severity = "medium"
    else:
        severity = "low"
        
    return {
        "damage": d,
        "reproducibility": r,
        "exploitability": e,
        "affected_users": a,
        "discoverability": disc,
        "score": score,
        "severity": severity,
    }


def calculate_score(results: list[dict[str, Any]]) -> int:
    """Return integer score 0-100 based on DREAD severity penalties."""
    penalty = 0
    for result in results:
        # Compute dread details
        dread = result.get("dread_details")
        if not dread:
            status = result.get("status", "PASS")
            orig_sev = result.get("severity", "INFO")
            dread = calculate_dread_details(status, orig_sev)
            
        sev = dread.get("severity", "info").lower()
        if sev == "high":
            penalty += 30
        elif sev == "medium":
            penalty += 15
        elif sev == "low":
            penalty += 5
            
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

