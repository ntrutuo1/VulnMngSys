from domain.protocols import Rule, RuleChecker, RuleComparisonResult, SystemCollector
from app_bootstrap.scanflow.evaluate import evaluate_rule_verdict

class SeceditChecker(RuleChecker):
    """Kiểm tra Security Policy dựa trên dữ liệu từ Secedit."""

    def can_handle(self, rule: Rule) -> bool:
        ps_check = str(rule.raw_spec.get("powershell_check", "")).lower()
        return "secpol.inf" in ps_check

    def check(self, rule: Rule, collector: SystemCollector) -> RuleComparisonResult:
        # Trong JSON Engine cũ, các khóa security policy được tìm kiếm trong powershell_check string
        # Ví dụ: ^MinimumPasswordLength, ^PasswordComplexity...
        import re
        ps_check = rule.raw_spec.get("powershell_check", "")
        match = re.search(r"\^([A-Za-z0-9_]+)", ps_check)
        if not match:
            return RuleComparisonResult(False, "MANUAL", "N/A", rule.expected, "Cannot extract key from powershell_check")
            
        key_name = match.group(1)
        
        # Security Policy được lưu trong SystemCollector
        secedit_policy = collector.get_secedit_policy()
        actual_val = secedit_policy.get(key_name)
        
        passed, verdict, _ = evaluate_rule_verdict(
            rule=rule.raw_spec,
            check_type="secedit",
            status="Collected",
            actual=str(actual_val),
            recommended=str(rule.expected)
        )
        
        return RuleComparisonResult(
            passed=passed,
            verdict=verdict,
            actual_value=actual_val,
            expected_value=rule.expected
        )
