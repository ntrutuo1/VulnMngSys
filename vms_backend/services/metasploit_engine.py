import re

from ..models import CveFinding


class MetasploitEngine:
    def __init__(self, repository, job_service, powershell_adapter, msf_adapter):
        self.repository = repository
        self.job_service = job_service
        self.powershell_adapter = powershell_adapter
        self.msf_adapter = msf_adapter

    def run_vulnerability_scan(self, scan):
        try:
            self.job_service.update_status(scan.scan_id, stage="Collecting Windows services", percent=25)
            services = self.powershell_adapter.execute_json(
                "Get-Service | Select Name,DisplayName,@{n='Status';e={$_.Status.ToString()}},@{n='StartType';e={$_.StartType.ToString()}} | ConvertTo-Json -Depth 2",
                [],
            )
            self.job_service.update_status(scan.scan_id, stage="Checking listening ports", percent=55)
            ports = self.powershell_adapter.execute_json(
                "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select LocalAddress,LocalPort,@{n='State';e={$_.State.ToString()}},OwningProcess | ConvertTo-Json -Depth 2",
                [],
            )
            self.job_service.update_status(scan.scan_id, stage="Checking installed software", percent=75)
            software = self.powershell_adapter.execute_json(
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where DisplayName | Select DisplayName,DisplayVersion,Publisher | ConvertTo-Json -Depth 2",
                [],
            )
            findings = self.evaluate_services(scan.scan_id, services, ports, software)
            scan.score = min(100, sum(finding.risk_score for finding in findings))
            scan.summary = {
                "services": len(services),
                "listeningPorts": sorted({item.get("LocalPort") for item in ports if item.get("LocalPort")}),
                "software": len(software),
            }
            scan.update_status("COMPLETED")
            self.repository.update_scan(scan)
            self.repository.save_cve_findings(findings)
            self.job_service.update_status(scan.scan_id, status="COMPLETED", stage="Completed", percent=100)
        except Exception as exc:
            self._fail(scan, "Service scan failed", str(exc))

    def evaluate_services(self, scan_id: str, services: list[dict], ports: list[dict], software: list[dict]):
        findings = []
        risky_services = {
            "RemoteRegistry": ("Remote Registry dang chay", "Remote Registry", "high", 25, "Tat service RemoteRegistry neu khong co nhu cau quan tri tu xa."),
            "TlntSvr": ("Telnet Server dang chay", "Telnet", "critical", 35, "Go bo Telnet, dung SSH/RDP co NLA hoac VPN."),
            "SNMP": ("SNMP dang chay", "SNMP", "medium", 12, "Kiem tra community string, gioi han ACL hoac tat neu khong dung."),
            "WinRM": ("WinRM dang chay", "WinRM", "medium", 12, "Bat HTTPS/kerberos va gioi han TrustedHosts."),
        }
        service_by_name = {service.get("Name"): service for service in services}
        for service_name, (evidence, affected, severity, score, patch_status) in risky_services.items():
            service = service_by_name.get(service_name)
            if service and service.get("Status") == "Running":
                findings.append(CveFinding(self.repository.new_id(), scan_id, f"{evidence}: {service.get('DisplayName')}", severity, affected_service=affected, risk_score=score, patch_status=patch_status))

        open_ports = {int(item.get("LocalPort")) for item in ports if str(item.get("State", "")).lower() == "listen" and str(item.get("LocalPort", "")).isdigit()}
        for port, title, severity, score in [(21, "FTP mo", "high", 25), (23, "Telnet mo", "critical", 35), (445, "SMB mo", "medium", 12), (3389, "RDP mo", "medium", 12), (5985, "WinRM HTTP mo", "medium", 12)]:
            if port in open_ports:
                findings.append(CveFinding(self.repository.new_id(), scan_id, f"TCP/{port} dang listen", severity, affected_service=title, risk_score=score, patch_status="Dong port tren firewall neu khong can, hoac gioi han IP quan tri."))

        weak_pattern = re.compile(r"(Java\(TM\).* (6|7|8 Update [0-9]{1,2})|Apache Tomcat (6|7)|Apache HTTP Server 2\.2|PHP (5\.|7\.0)|OpenSSL 1\.(0|1\.0))", re.I)
        for app in software:
            name = f"{app.get('DisplayName','')} {app.get('DisplayVersion','')}".strip()
            if weak_pattern.search(name):
                findings.append(CveFinding(self.repository.new_id(), scan_id, name[:220], "high", affected_service="Outdated software", risk_score=25, patch_status="Nang cap len ban duoc nha cung cap ho tro va quet lai."))
        return findings

    def _fail(self, scan, title, evidence):
        scan.score = 25
        scan.update_status("FAILED")
        self.repository.update_scan(scan)
        self.repository.save_cve_findings([CveFinding(self.repository.new_id(), scan.scan_id, evidence, "high", affected_service=title, risk_score=25, patch_status="Chay app bang quyen Admin va thu lai.")])
        self.job_service.update_status(scan.scan_id, status="FAILED", stage="Failed", percent=100)
