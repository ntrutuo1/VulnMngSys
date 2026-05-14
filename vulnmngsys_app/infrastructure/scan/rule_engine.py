from __future__ import annotations

from dataclasses import dataclass

from ...domain.models import ModuleDefinition, RuleResult


def _find_first_line_number(raw_text: str, needles: list[str]) -> int:
    lowered_needles = [needle.lower() for needle in needles if needle]
    if not lowered_needles:
        return 0

    for line_number, line in enumerate(raw_text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        content = stripped.split("#", 1)[0].strip()
        if not content:
            continue
        line_lower = content.lower()
        if any(needle in line_lower for needle in lowered_needles):
            return line_number
    return 0


def _read_line_content(raw_text: str, line_number: int) -> str:
    if line_number <= 0:
        return ""
    lines = raw_text.splitlines()
    if line_number > len(lines):
        return ""
    return lines[line_number - 1].strip()


def _first_baseline_line(baseline: str) -> str:
    if not baseline:
        return ""
    for line in baseline.splitlines():
        trimmed = line.strip()
        if trimmed:
            return trimmed
    return ""


@dataclass(frozen=True, slots=True)
class RuleEngineResult:
    results: list[RuleResult]


class RuleEngine:
    def evaluate(
        self,
        module: ModuleDefinition,
        config_texts: dict[str, str],
        resolved_paths: dict[str, str],
    ) -> RuleEngineResult:
        results: list[RuleResult] = []
        for check in module.checks:
            raw_text = config_texts.get(check.config_file_key, "")
            passed, reason = check.evaluator(raw_text)

            metadata = module.check_metadata.get(check.code, {})
            search_terms = metadata.get("search", "").split("|") if metadata.get("search") else []
            config_line = _find_first_line_number(raw_text, search_terms)
            config_path = resolved_paths.get(check.config_file_key, "")
            baseline = metadata.get("baseline", "")
            explanation = check.explanation or metadata.get("explanation", "")
            actual_line = _read_line_content(raw_text, config_line)
            results.append(
                RuleResult(
                    code=check.code,
                    title=check.title,
                    severity=check.severity,
                    weight=check.weight,
                    passed=passed,
                    reason=reason,
                    config_path=config_path,
                    config_line=config_line,
                    baseline=baseline,
                    explanation=explanation,
                    actual_line=actual_line,
                    suggested_line=_first_baseline_line(baseline),
                )
            )

        return RuleEngineResult(results=results)