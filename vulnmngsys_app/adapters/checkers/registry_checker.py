from typing import Any
from vulnmngsys_app.models.protocols import Rule, RuleChecker, RuleComparisonResult, SystemCollector
from vulnmngsys_app.services.scanflow.evaluate import evaluate_registry_expected


def _parse_registry_path(reg_path: str) -> tuple[str, str, str] | None:
    if ":" not in reg_path:
        return None

    path_part, value_name = reg_path.split(":", 1)
    segments = [segment for segment in path_part.split("\\") if segment]
    if len(segments) < 2 or not value_name:
        return None

    hive = segments[0]
    key = "\\".join(segments[1:])
    return hive, key, value_name


class RegistryChecker(RuleChecker):
    """Kiểm tra cấu hình Registry."""

    def can_handle(self, rule: Rule) -> bool:
        # Nếu rule có registry_path và KHÔNG PHẢI là quét tất cả User SIDs
        reg_path = str(rule.raw_spec.get("registry_path") or rule.raw_spec.get("registry") or "")
        return bool(reg_path) and "[USER SID]" not in reg_path

    def check(self, rule: Rule, collector: SystemCollector) -> RuleComparisonResult:
        reg_path = str(rule.raw_spec.get("registry_path") or rule.raw_spec.get("registry") or "")
        
        # Parse registry path
        parsed = _parse_registry_path(reg_path)
        if parsed is None:
            return RuleComparisonResult(False, "ERROR", None, rule.expected, "Invalid registry_path")
        hive, key, value_name = parsed
        
        actual_val, val_type = collector.get_registry_value(hive, key, value_name)
        
        if val_type == "NotFound" or val_type == "Error":
            # Xử lý logic key không tồn tại (missing value passes)
            if self._missing_value_passes(rule.raw_spec):
                return RuleComparisonResult(True, "PASS", "Not Configured", rule.expected)
            return RuleComparisonResult(False, "FAIL", "Not Configured", rule.expected)
            
        # So sánh dựa theo hàm có sẵn
        passed = evaluate_registry_expected(rule.raw_spec, actual_val)
        verdict = "PASS" if passed else "FAIL"
        
        return RuleComparisonResult(
            passed=passed,
            verdict=verdict,
            actual_value=actual_val,
            expected_value=rule.expected
        )

    def _missing_value_passes(self, spec: dict[str, Any]) -> bool:
        op = str(spec.get("operator", "")).casefold()
        expected = spec.get("expected")
        if op == "notequal":
            return True
        if op in {"==", ""} and expected == "Not Configured":
            return True
        return False
