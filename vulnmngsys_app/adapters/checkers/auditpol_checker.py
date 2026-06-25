from vulnmngsys_app.models.protocols import Rule, RuleChecker, RuleComparisonResult, SystemCollector
from vulnmngsys_app.services.scanflow.evaluate import evaluate_rule_verdict

class AuditpolChecker(RuleChecker):
    """Kiểm tra Audit Policy."""

    def can_handle(self, rule: Rule) -> bool:
        ps_check = str(rule.raw_spec.get("powershell_check", "")).lower()
        return "auditpol /get" in ps_check

    def check(self, rule: Rule, collector: SystemCollector) -> RuleComparisonResult:
        import re
        ps_check = rule.raw_spec.get("powershell_check", "")
        # Lấy GUID: auditpol /get /category:"{0ccee921-4360-11d1-8b02-00c04fc2ddea}"
        match = re.search(r"({[A-Fa-f0-9\-]+})", ps_check)
        if not match:
            return RuleComparisonResult(False, "MANUAL", "N/A", rule.expected, "Cannot extract GUID")
        guid = match.group(1).lower()
        audit_policy = collector.get_audit_policy()
        actual_val = audit_policy.get(guid, "No Auditing")
        
        passed, verdict, _ = evaluate_rule_verdict(
            rule=rule.raw_spec,
            check_type="auditpol",
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
