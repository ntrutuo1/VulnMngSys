from __future__ import annotations

from pathlib import Path

from .models import ModuleDefinition, RuleResult, ScanReport, ScanSummary


def _resolve_existing_path(candidates: list[str]) -> str:
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return candidates[0]


def _read_text(path: str) -> str:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(path)
    return file_path.read_text(encoding="utf-8", errors="ignore")


def _grade_for_index(index: int) -> str:
    if index >= 90:
        return "A"
    if index >= 75:
        return "B"
    if index >= 60:
        return "C"
    return "D"


def scan_module(module: ModuleDefinition) -> ScanReport:
    used_paths: dict[str, str] = {
        key: _resolve_existing_path(paths) for key, paths in module.config_paths.items()
    }

    cache: dict[str, str] = {}
    for key, path in used_paths.items():
        cache[key] = _read_text(path)

    results: list[RuleResult] = []
    total_weight = 0
    passed_weight = 0

    for check in module.checks:
        raw_text = cache.get(check.config_file_key, "")
        passed, reason = check.evaluator(raw_text)
        total_weight += check.weight
        if passed:
            passed_weight += check.weight

        results.append(
            RuleResult(
                code=check.code,
                title=check.title,
                severity=check.severity,
                weight=check.weight,
                passed=passed,
                reason=reason,
            )
        )

    total_checks = len(results)
    passed_checks = len([item for item in results if item.passed])
    failed_checks = total_checks - passed_checks

    hardening_index = int(round((passed_weight / total_weight) * 100)) if total_weight else 0
    summary = ScanSummary(
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        total_weight=total_weight,
        passed_weight=passed_weight,
        hardening_index=hardening_index,
        grade=_grade_for_index(hardening_index),
        warnings=[],
    )

    for item in results:
        if not item.passed and item.severity.lower() in {"critical", "high"}:
            summary.warnings.append(f"{item.code}: {item.title}")

    return ScanReport(
        module=module,
        used_config_paths=used_paths,
        summary=summary,
        results=results,
    )
