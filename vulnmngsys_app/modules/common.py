from __future__ import annotations

from pathlib import Path

from ..models import RuleCheck


SEVERITY_WEIGHT = {
    "low": 1,
    "medium": 4,
    "high": 7,
    "critical": 10,
}


def rules_file(name: str) -> str:
    return str((Path(__file__).resolve().parents[2] / "rules" / name).resolve())


def make_directive_check(
    code: str,
    title: str,
    severity: str,
    config_file_key: str,
    directive: str,
    expected_value: str,
    explanation: str = "",
) -> RuleCheck:
    expected_normalized = expected_value.strip().lower()

    def evaluate(raw_text: str) -> tuple[bool, str]:
        effective = extract_last_directive_value(raw_text, directive)
        if effective is None:
            return False, f"Missing directive: {directive}"
        actual = " ".join(effective.split()).lower()
        if actual != expected_normalized:
            return False, f"Expected '{directive} {expected_value}', got '{directive} {effective}'"
        return True, "Matched expected value"

    return RuleCheck(
        code=code,
        title=title,
        severity=severity,
        weight=SEVERITY_WEIGHT[severity.lower()],
        config_file_key=config_file_key,
        evaluator=evaluate,
        explanation=explanation,
    )


def extract_last_directive_value(raw_text: str, directive: str) -> str | None:
    matched_value: str | None = None
    lookup = directive.lower()
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        content = stripped.split("#", 1)[0].strip()
        if not content:
            continue
        parts = content.split()
        if not parts:
            continue
        key = parts[0].lower()
        if key == lookup:
            matched_value = " ".join(parts[1:]).strip()
    return matched_value


def contains_xml_predicate(
    code: str,
    title: str,
    severity: str,
    config_file_key: str,
    predicate,
    success_message: str,
    failure_message: str,
    explanation: str = "",
) -> RuleCheck:
    def evaluate(raw_text: str) -> tuple[bool, str]:
        passed = predicate(raw_text)
        if passed:
            return True, success_message
        return False, failure_message

    return RuleCheck(
        code=code,
        title=title,
        severity=severity,
        weight=SEVERITY_WEIGHT[severity.lower()],
        config_file_key=config_file_key,
        evaluator=evaluate,
        explanation=explanation,
    )
