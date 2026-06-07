"""Calculate a 0–100 security score from IIS MSF audit results."""
from __future__ import annotations

from typing import Any

# Points deducted per finding type (out of 100-point baseline)
_PENALTY: dict[str, int] = {
    "FAIL": 15,
    "WARNING": 5,
    "ERROR": 8,
}


def calculate_score(results: list[dict[str, Any]]) -> int:
    """Return integer score 0–100.

    - SKIPPED and INFO results are excluded from scoring.
    - PASS results contribute positively.
    - FAIL, WARNING, ERROR deduct points.
    """
    scorable = [r for r in results if r.get("status") not in ("SKIPPED", "INFO")]
    if not scorable:
        return 100

    total = len(scorable)
    penalty = sum(_PENALTY.get(r.get("status", ""), 0) for r in scorable)

    # Base score: 100 points minus penalties per finding
    raw = 100 - penalty
    # Clamp to [0, 100]
    return max(0, min(100, raw))


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
