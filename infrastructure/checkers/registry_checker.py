from typing import Any
from domain.protocols import Rule, RuleChecker, RuleComparisonResult, SystemCollector
from app_bootstrap.scanflow.evaluate import evaluate_numeric_expected, evaluate_registry_expected

class RegistryChecker(RuleChecker):
    """Kiểm tra cấu hình Registry."""

    def can_handle(self, rule: Rule) -> bool:
        # Nếu rule có registry_path và KHÔNG PHẢI là quét tất cả User SIDs
        reg_path = rule.raw_spec.get("registry_path", "")
        return bool(reg_path) and "[USER SID]" not in reg_path

    def check(self, rule: Rule, collector: SystemCollector) -> RuleComparisonResult:
        reg_path = rule.raw_spec.get("registry_path")
        
        # Parse registry path
        if ":" not in reg_path:
            return RuleComparisonResult(False, "ERROR", None, rule.expected, "Invalid registry_path")
            
        hive, subkey_name = reg_path.split(":", 1)
        if "\\" not in subkey_name:
            return RuleComparisonResult(False, "ERROR", None, rule.expected, "Invalid subkey_name")
            
        parts = subkey_name.rsplit("\\", 1)
        key = parts[0]
        value_name = parts[1]
        
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
