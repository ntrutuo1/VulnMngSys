from __future__ import annotations

import re
from typing import Any

from .constants import AUDITPOL_BITMASKS, AUDITPOL_TEXT_TO_MASK


def format_expected_display(expected: Any, description: str = "") -> str:
    if description and str(description).strip():
        return str(description).strip()
    if expected is None:
        return ""
    if isinstance(expected, str):
        return expected.strip()
    if isinstance(expected, (list, tuple)):
        items = [str(item).strip() for item in expected if str(item).strip()]
        return "No One" if not items else ", ".join(sorted(items))
    if isinstance(expected, dict):
        parts = [f"{key}={value}" for key, value in expected.items()]
        return ", ".join(parts)
    return str(expected).strip()


def _to_number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def evaluate_numeric_expected(expected: Any, actual: str) -> bool:
    if not isinstance(expected, dict):
        number = _to_number(expected)
        actual_number = _to_number(actual)
        if number is not None and actual_number is not None:
            return actual_number == number
        return str(expected).strip().lower() in actual.lower()

    actual_number = _to_number(actual)
    if actual_number is None:
        return False

    if "min" in expected and actual_number < float(expected["min"]):
        return False
    if "max" in expected and actual_number > float(expected["max"]):
        return False
    if "gt" in expected and not (actual_number > float(expected["gt"])):
        return False
    if "gte" in expected and not (actual_number >= float(expected["gte"])):
        return False
    if "eq" in expected and actual_number != float(expected["eq"]):
        return False
    return True


def evaluate_user_right_expected(rule: dict[str, Any], actual: str) -> bool:
    expected_raw = rule.get("expected")
    if isinstance(expected_raw, list):
        expected_groups = [str(item).strip() for item in expected_raw]
    else:
        expected_groups = []

    actual_groups = [part.strip() for part in actual.split(",") if part.strip()]
    if actual_groups == ["No One"]:
        actual_groups = []

    match_mode = str(rule.get("match") or "exact").lower()
    if match_mode == "includes":
        if not expected_groups:
            return len(actual_groups) > 0
        return all(group in actual_groups for group in expected_groups)

    expected_sorted = ",".join(sorted(expected_groups))
    actual_sorted = ",".join(sorted(actual_groups))
    if not expected_groups and not actual_groups:
        return True
    return expected_sorted == actual_sorted


def evaluate_local_account_expected(rule: dict[str, Any], actual: str) -> bool:
    expected = str(rule.get("expected") or "").strip()
    actual_lower = actual.lower()

    if expected == "Disabled":
        return actual_lower == "disabled"
    if expected.startswith("Not "):
        forbidden = expected[4:].strip().strip("'\"")
        return actual_lower != forbidden.lower()
    return expected.lower() in actual_lower


def evaluate_auditpol_expected(expected: Any, actual: str) -> bool:
    if expected is None:
        return True

    def _auditpol_mask(value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            numeric = int(value)
            return AUDITPOL_BITMASKS.get(numeric, numeric if numeric >= 0 else None)

        text = str(value).strip().lower()
        if not text:
            return None
        if text in AUDITPOL_TEXT_TO_MASK:
            return AUDITPOL_TEXT_TO_MASK[text]
        if text.isdigit():
            numeric = int(text)
            return AUDITPOL_BITMASKS.get(numeric, numeric if numeric >= 0 else None)
        return None

    expected_mask = _auditpol_mask(expected)
    actual_mask = _auditpol_mask(actual)

    if expected_mask is not None and actual_mask is not None:
        return (actual_mask & expected_mask) == expected_mask

    expected_text = str(expected).strip().lower()
    actual_lower = actual.lower()
    tokens = [token.strip() for token in re.split(r",| and |/", expected_text) if token.strip()]
    if not tokens:
        return expected_text in actual_lower
    return all(token in actual_lower for token in tokens)


def evaluate_registry_expected(rule: dict[str, Any], actual: Any) -> bool:
    actual_text = str(actual).strip()
    if "registry_value" in rule:
        return str(rule.get("registry_value")).strip() == actual_text

    expected = rule.get("expected")
    if isinstance(expected, dict):
        return evaluate_numeric_expected(expected, actual_text)

    if isinstance(expected, (int, float)):
        return str(int(expected)) == actual_text

    if isinstance(expected, str):
        expected_lower = expected.strip().lower()
        if expected_lower in {"enabled", "disabled"} and actual_text in {"0", "1"}:
            target = "1" if expected_lower == "enabled" else "0"
            return actual_text == target
        return expected_lower in actual_text.lower()

    return True


def evaluate_rule_verdict(
    *,
    rule: dict[str, Any],
    check_type: str,
    status: str,
    actual: str,
    recommended: str = "",
) -> tuple[bool, str, str]:
    """Return (passed, verdict, expected_display)."""
    expected_display = recommended or format_expected_display(
        rule.get("expected"),
        str(rule.get("description") or ""),
    )

    if status in {"NoDirectProbe", "DisabledForSafety", "UnsupportedRegistrySpec", "UnsupportedRegistryPath"}:
        return False, "MANUAL", expected_display

    if status not in {"Collected"}:
        return False, "MANUAL", expected_display

    rule_type = str(rule.get("check_type") or rule.get("type") or check_type or "").lower()
    passed = False

    if rule_type in {"secedit", "security_policy", "securityoptions", "security_option"}:
        passed = evaluate_numeric_expected(rule.get("expected"), actual)
    elif rule_type == "user_right":
        passed = evaluate_user_right_expected(rule, actual)
    elif rule_type == "local_account":
        passed = evaluate_local_account_expected(rule, actual)
    elif rule_type == "auditpol":
        passed = evaluate_auditpol_expected(rule.get("expected"), actual)
    elif rule_type in {"registry-multi", "registry"} or check_type.startswith("registry"):
        expected_list = rule.get("expected")
        if isinstance(expected_list, list):
            # registry-multi emits one row per candidate; each row uses its own Recommended.
            # Here we accept match by token/number against the Recommended already in expected_display.
            passed = str(expected_display).strip().lower() in str(actual).strip().lower()
        else:
            passed = evaluate_registry_expected(rule, actual)
    elif "registry_value" in rule:
        passed = evaluate_registry_expected(rule, actual)
        expected_display = str(rule.get("registry_value"))
    else:
        passed = evaluate_registry_expected(rule, actual) if rule.get("expected") is not None else (
            str(rule.get("recommended") or "").lower() in actual.lower() if rule.get("recommended") else True
        )

    verdict = "PASS" if passed else "FAIL"
    return passed, verdict, expected_display
