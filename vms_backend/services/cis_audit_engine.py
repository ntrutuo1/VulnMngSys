from ..models import CisFinding


class CisAuditEngine:
    def __init__(self, repository, job_service, powershell_adapter):
        self.repository = repository
        self.job_service = job_service
        self.powershell_adapter = powershell_adapter

    def run_config_audit(self, scan):
        checks = [
            ("CIS-WIN-FW", "Firewall Windows", "Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false} | Measure | % Count", lambda value: value == "0"),
            ("CIS-WIN-SMB1", "SMBv1", "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue).State", lambda value: value != "Enabled"),
            ("CIS-WIN-UAC", "UAC", "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA", lambda value: value != "0"),
        ]
        try:
            findings = []
            for index, (rule_id, title, script, is_passed) in enumerate(checks, 1):
                self.job_service.update_status(scan.scan_id, stage=title, percent=round(index / len(checks) * 85))
                evidence = self.powershell_adapter.execute_cmd(script, timeout=15)
                passed = is_passed(evidence)
                findings.append(CisFinding(self.repository.new_id(), scan.scan_id, title, evidence, "PASSED" if passed else "FAILED", rule_id=rule_id, is_passed=passed))
            failed = [finding for finding in findings if not finding.is_passed]
            scan.score = min(100, len(failed) * 12)
            scan.summary = {"checks": len(checks), "failed": len(failed)}
            scan.update_status("COMPLETED")
            self.repository.update_scan(scan)
            self.repository.save_cis_findings(findings)
            self.job_service.update_status(scan.scan_id, status="COMPLETED", stage="Completed", percent=100)
        except Exception as exc:
            scan.score = 25
            scan.update_status("FAILED")
            self.repository.update_scan(scan)
            self.repository.save_cis_findings([CisFinding(self.repository.new_id(), scan.scan_id, "CIS scan failed", str(exc), "FAILED", is_passed=False)])
            self.job_service.update_status(scan.scan_id, status="FAILED", stage="Failed", percent=100)
