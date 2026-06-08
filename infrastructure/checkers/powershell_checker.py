from domain.protocols import Rule, RuleChecker, RuleComparisonResult, SystemCollector
from app_bootstrap.scanflow.evaluate import evaluate_rule_verdict
from app_bootstrap.scanflow.security import validate_powershell_check


class PowerShellChecker(RuleChecker):
    """Checks configuration through a safe PowerShell probe."""

    def can_handle(self, rule: Rule) -> bool:
        ps_check = rule.raw_spec.get("powershell_check", "")
        return bool(ps_check) and "secpol.inf" not in ps_check.lower() and "auditpol /get" not in ps_check.lower()

    def check(self, rule: Rule, collector: SystemCollector) -> RuleComparisonResult:
        ps_check = rule.raw_spec.get("powershell_check", "")
        validate_powershell_check(str(ps_check))
        actual_val = collector.run_powershell(ps_check)

        passed, verdict, _ = evaluate_rule_verdict(
            rule=rule.raw_spec,
            check_type="powershell",
            status="Collected",
            actual=str(actual_val),
            recommended=str(rule.expected),
        )

        return RuleComparisonResult(
            passed=passed,
            verdict=verdict,
            actual_value=actual_val,
            expected_value=rule.expected,
        )
