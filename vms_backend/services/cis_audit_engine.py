import json
import operator

from ..models import CisFinding


class CisAuditEngine:
    def __init__(self, repository, rule_repository, job_service, powershell_adapter):
        self.repository = repository
        self.rule_repository = rule_repository
        self.job_service = job_service
        self.powershell_adapter = powershell_adapter

    def run_config_audit(self, scan, benchmark=None):
        benchmark = benchmark or self.detect_benchmark()
        rules = self.rule_repository.list_enabled(benchmark)
        try:
            findings = []
            skipped = 0
            passed_count = 0
            total = max(len(rules), 1)
            for index, rule in enumerate(rules, 1):
                self.job_service.update_status(scan.scan_id, stage=rule.title[:90], percent=round(index / total * 90))
                result = self.evaluate_rule(rule)
                if result is None:
                    skipped += 1
                    continue
                passed, evidence = result
                if passed:
                    passed_count += 1
                    continue
                findings.append(
                    CisFinding(
                        id=self.repository.new_id(),
                        scan_id=scan.scan_id,
                        title=rule.title,
                        evidence=evidence,
                        status="FAILED",
                        remediation=rule.remediation,
                        rule_id=rule.rule_id,
                        is_passed=False,
                        registry_key=rule.registry_path,
                    )
                )
            scan.score = round(len(findings) / max(len(rules), 1) * 100, 1)
            scan.summary = {"benchmark": benchmark or "ALL", "rules": len(rules), "passed": passed_count, "failed": len(findings), "skipped": skipped}
            scan.update_status("COMPLETED")
            self.repository.update_scan(scan)
            self.repository.save_cis_findings(findings)
            self.job_service.update_status(scan.scan_id, status="COMPLETED", stage="Completed", percent=100)
        except Exception as exc:
            scan.score = 25
            scan.update_status("FAILED")
            self.repository.update_scan(scan)
            self.repository.save_cis_findings([CisFinding(self.repository.new_id(), scan.scan_id, "CIS scan failed", str(exc), "FAILED", remediation="Check the rule set and PowerShell execution privileges.", is_passed=False)])
            self.job_service.update_status(scan.scan_id, status="FAILED", stage="Failed", percent=100)

    def detect_benchmark(self):
        try:
            os_text = self.powershell_adapter.execute_cmd(
                "(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption) + ' ' + "
                "(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber)",
                timeout=10,
            )
        except Exception:
            os_text = ""
        normalized = os_text.lower()
        if "2025" in normalized:
            return "CIS-WIN2025"
        if "2022" in normalized:
            return "CIS-WIN2022_STANDARD"
        numbers = [int(part) for part in normalized.replace(".", " ").split() if part.isdigit()]
        build = max(numbers) if numbers else 0
        if build >= 26000:
            return "CIS-WIN2025"
        if build >= 20348:
            return "CIS-WIN2022_STANDARD"
        benchmarks = self.rule_repository.list_benchmarks()
        return benchmarks[-1]["benchmark"] if benchmarks else None

    def evaluate_rule(self, rule):
        try:
            evidence = self.powershell_adapter.execute_cmd(rule.powershell_check, timeout=20).strip()
        except Exception:
            evidence = ""
            
        # Treat unavailable or non-existent registry paths/properties as empty string to evaluate them
        if self._is_unavailable(evidence):
            actual_check = ""
        else:
            actual_check = evidence

        passed = self._compare(actual_check, json.loads(rule.expected), rule.operator)
        return passed, evidence

    def _is_unavailable(self, evidence: str):
        value = evidence.strip()
        if value == "":
            return True
        lowered = value.lower()
        return any(
            marker in lowered
            for marker in [
                "not found",
                "cannot find",
                "does not exist",
                "no data",
                "null",
            ]
        )

    def _compare(self, actual, expected, op):
        actual_value = self._coerce(actual)
        expected_value = self._coerce(expected)
        comparisons = {
            "==": operator.eq,
            "!=": operator.ne,
            ">=": operator.ge,
            "<=": operator.le,
            ">": operator.gt,
            "<": operator.lt,
        }
        if op == "<=_not_0":
            return actual_value != 0 and actual_value <= expected_value
        if op == "in":
            return actual_value in expected_value
        try:
            return comparisons.get(op, operator.eq)(actual_value, expected_value)
        except TypeError:
            return comparisons.get(op, operator.eq)(str(actual_value), str(expected_value))

    def _coerce(self, value):
        if isinstance(value, (int, float, list)):
            return value
        text = str(value).strip()
        if text.lower() in {"true", "false"}:
            return text.lower() == "true"
        try:
            return int(text)
        except ValueError:
            pass
        try:
            return float(text)
        except ValueError:
            return text
