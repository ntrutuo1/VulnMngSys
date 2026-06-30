import os
import re
import socket
from pathlib import Path

from ..models import CveFinding, TARGET_SERVICES




class MetasploitEngine:
    def __init__(self, repository, cve_repository, job_service, powershell_adapter, msf_adapter):
        self.repository = repository
        self.cve_repository = cve_repository
        self.job_service = job_service
        self.powershell_adapter = powershell_adapter
        self.msf_adapter = msf_adapter

    def run_vulnerability_scan(self, scan, scan_options: dict = None):
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
            self.job_service.update_status(scan.scan_id, stage="Matching CVEs and Metasploit modules", percent=88)
            scan_record = self.repository.find_scan(scan.scan_id) or {}
            service_context = self.detect_service_context(services, ports, software)
            # Intersect with target services list to extract only the matching ones
            service_context["services"] = service_context["services"] & TARGET_SERVICES.keys()
            service_context["target"] = scan_record.get("target") or os.environ.get("VMS_HOST") or self._get_local_ip()
            findings = self.evaluate_services(scan.scan_id, services, ports, software)
            cve_findings, modules_used = self.evaluate_cves(scan.scan_id, service_context, scan_options)
            findings.extend(cve_findings)
            scan.score = min(100, sum(finding.risk_score for finding in findings))
            scan.summary = {
                "services": len(services),
                "listeningPorts": sorted({item.get("LocalPort") for item in ports if item.get("LocalPort")}),
                "software": len(software),
                "detectedServices": sorted(service_context["services"]),
                "modulesUsed": sorted(list(modules_used)),
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
            "RemoteRegistry": ("Remote Registry is running", "Remote Registry", "high", 25, "Disable Remote Registry unless remote administration requires it."),
            "TlntSvr": ("Telnet Server is running", "Telnet", "critical", 35, "Remove Telnet and use SSH, RDP with NLA, or VPN."),
            "SNMP": ("SNMP is running", "SNMP", "medium", 12, "Review community strings, restrict ACLs, or disable SNMP if unused."),
        }
        service_by_name = {service.get("Name"): service for service in services}
        for service_name, (evidence, affected, severity, score, patch_status) in risky_services.items():
            service = service_by_name.get(service_name)
            if service and service.get("Status") == "Running":
                findings.append(CveFinding(self.repository.new_id(), scan_id, f"{evidence}: {service.get('DisplayName')}", severity, affected_service=affected, risk_score=score, patch_status=patch_status))

        open_ports = {int(item.get("LocalPort")) for item in ports if str(item.get("State", "")).lower() == "listen" and str(item.get("LocalPort", "")).isdigit()}
        for port, title, severity, score in [(21, "FTP open", "high", 25), (23, "Telnet open", "critical", 35)]:
            if port in open_ports:
                findings.append(CveFinding(self.repository.new_id(), scan_id, f"TCP/{port} is listening", severity, affected_service=title, risk_score=score, patch_status="Close the port in Windows Firewall if unused, or restrict it to trusted admin IPs."))

        weak_pattern = re.compile(r"(Java\(TM\).* (6|7|8 Update [0-9]{1,2})|Apache Tomcat (6|7)|Apache HTTP Server 2\.2|PHP (5\.|7\.0)|OpenSSL 1\.(0|1\.0))", re.I)
        for app in software:
            name = f"{app.get('DisplayName','')} {app.get('DisplayVersion','')}".strip()
            if weak_pattern.search(name):
                findings.append(CveFinding(self.repository.new_id(), scan_id, name[:220], "high", affected_service="Outdated software", risk_score=25, patch_status="Upgrade to a supported vendor version and scan again."))
        return findings

    def detect_service_context(self, services: list[dict], ports: list[dict], software: list[dict]):
        service_names = {str(service.get("Name", "")).lower(): service for service in services}
        display_names = " ".join(str(service.get("DisplayName", "")) for service in services).lower()
        software_names = " ".join(f"{app.get('DisplayName', '')} {app.get('Publisher', '')}" for app in software).lower()
        open_ports = {int(item.get("LocalPort")) for item in ports if str(item.get("State", "")).lower() == "listen" and str(item.get("LocalPort", "")).isdigit()}
        detected = set()
        if "w3svc" in service_names or "iis" in display_names or any(port in open_ports for port in [80, 443, 8080, 8443]):
            detected.add("iis")
        if 445 in open_ports or "lanmanserver" in service_names:
            detected.add("smb")
        if "webclient" in service_names or "webdav" in display_names or "webdav" in software_names:
            detected.add("webdav")
        if 443 in open_ports or "http/2" in software_names or "iis" in detected:
            detected.add("http2")
        if "msdepsvc" in service_names or "web deploy" in software_names or 8172 in open_ports:
            detected.add("web_deploy")
        if "wsusservice" in service_names or "wsauserv" in service_names or any(port in open_ports for port in [8530, 8531]):
            detected.add("wsus")
        if 3389 in open_ports or "termservice" in service_names:
            detected.add("rdp")
        if 2049 in open_ports or "nfs" in service_names:
            detected.add("nfs")
        if 135 in open_ports or "rpcss" in service_names:
            detected.add("rpc")
        if "spooler" in service_names:
            detected.add("spooler")
        if 5985 in open_ports or 5986 in open_ports or "winrm" in service_names:
            detected.add("winrm")
        return {"services": detected, "ports": open_ports}

    def is_ignored(self, identifier: str) -> bool:
        if not identifier:
            return False
        ignore_file = Path("d:/VulnMngSys/VulnMngSys/.ignore")
        if not ignore_file.exists():
            return False
        try:
            lines = ignore_file.read_text(encoding="utf-8").splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.upper() == identifier.upper():
                    return True
        except Exception:
            pass
        return False

    def evaluate_cves(self, scan_id: str, context: dict, scan_options: dict = None):
        findings = []
        modules_used = set()
        
        # 1. Get all Metasploit modules directly mapped to the detected services
        matched_module_pairs = self.cve_repository.find_modules_for_services(context["services"])
        
        for cve, module in matched_module_pairs:
            if not module:
                continue
            if self.is_ignored(cve.cve_id) or self.is_ignored(module.module_path):
                continue
                
            modules_used.add(module.module_path)
            
            # Prevent execution of standard exploit modules during scan (except the 2 custom ones)
            is_exploit = module.module_type == "exploit" or "exploit" in module.module_path.lower()
            is_custom_module = "web_deploy" in module.module_path or "http2" in module.module_path or "53772" in module.module_path or "49975" in module.module_path
            
            if is_exploit and not is_custom_module:
                severity = self._severity(cve.max_cvss_base_score)
                risk_score = float(cve.max_cvss_base_score or 5)
                findings.append(
                    CveFinding(
                        self.repository.new_id(),
                        scan_id,
                        f"Vulnerability match found: {cve.cve_id}. Metasploit exploit module {module.module_path} is available. (Exploit execution skipped for safety). Summary: {cve.summary}",
                        severity,
                        cve_id=cve.cve_id,
                        affected_service=", ".join(cve.service_keywords),
                        msf_module=module.module_path,
                        risk_score=risk_score,
                        patch_status=f"Remediation is available for {cve.cve_id}. Apply the latest security updates."
                    )
                )
                continue

            options, missing = self.build_module_options(module, context, scan_options)
            if missing:
                findings.append(
                    CveFinding(
                        self.repository.new_id(),
                        scan_id,
                        f"Metasploit module {module.module_path} matched but was not run. Missing required options: {', '.join(missing)}",
                        "medium",
                        cve_id=cve.cve_id,
                        affected_service=", ".join(cve.service_keywords),
                        msf_module=module.module_path,
                        risk_score=8,
                        patch_status="Provide the missing Metasploit options before running this module.",
                    )
                )
                continue
            
            result = self.msf_adapter.execute_module(module.module_path, options, timeout=90)
            evidence_text = result.get("evidence") or ""
            
            # Check for actual vulnerability confirmation (real evidence)
            is_vulnerable = False
            vuln_line = ""
            for line in evidence_text.splitlines():
                line_str = line.strip()
                if "The target is vulnerable." in line_str:
                    is_vulnerable = True
                    vuln_line = line_str
                    break
                elif "[+]" in line_str or "vulnerable" in line_str.lower():
                    if "not vulnerable" not in line_str.lower() and "safe" not in line_str.lower():
                        is_vulnerable = True
                        vuln_line = line_str
                        break
            
            if is_vulnerable:
                severity = self._severity(cve.max_cvss_base_score)
                risk_score = float(cve.max_cvss_base_score or 5)
                patch_status = f"Metasploit status: {result['status']}. Confirmed vulnerable. Review remediation for {cve.cve_id}."
                evidence_text = vuln_line or "The target is vulnerable."
            else:
                severity = "low"
                risk_score = 0.0
                patch_status = f"Metasploit status: {result['status']}. Scanned but vulnerability was NOT confirmed by the module output."
                evidence_text = f"Scanned: {module.module_path} executed but vulnerability was not confirmed."
                
            findings.append(
                CveFinding(
                    self.repository.new_id(),
                    scan_id,
                    evidence_text,
                    severity,
                    cve_id=cve.cve_id,
                    affected_service=", ".join(cve.service_keywords),
                    msf_module=module.module_path,
                    risk_score=risk_score,
                    patch_status=patch_status,
                )
            )

        # 2. Append CVEs matched by services that have no Metasploit modules mapped in the database
        all_cve_pairs = self.cve_repository.find_for_services(context["services"])
        for cve, module in all_cve_pairs:
            if not module:
                if self.is_ignored(cve.cve_id):
                    continue
                findings.append(
                    CveFinding(
                        self.repository.new_id(),
                        scan_id,
                        f"Detected service match: {', '.join(sorted(set(cve.service_keywords) & context['services']))}. {cve.summary}",
                        self._severity(cve.max_cvss_base_score),
                        cve_id=cve.cve_id,
                        affected_service=", ".join(cve.service_keywords),
                        risk_score=float(cve.max_cvss_base_score or 5),
                        patch_status="No Metasploit module was mapped for this CVE in the local database.",
                    )
                )
                
        return findings, modules_used

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def build_module_options(self, module, context, scan_options: dict = None):
        ports = context["ports"]
        target = context.get("target") or self._get_local_ip()
        options = dict(module.default_options)
        
        # Override with scan_options if provided
        if scan_options:
            for k, v in scan_options.items():
                if v is not None and v != "":
                    upper_key = k.upper()
                    if upper_key == "TARGET":
                        # Skip overriding 'TARGET' option (which is the Metasploit target OS index) with target host IP
                        continue
                    options[upper_key] = v
                    
        options.setdefault("RHOSTS", target)
        options.setdefault("RHOST", target)
        
        # Scope port/service specific options based on target module paths to prevent cross-pollution
        if "http2_bomb" in module.module_path or "49975" in module.module_path:
            options.setdefault("RPORT", 443 if 443 in ports else 80)
            options.setdefault("SSL", 443 in ports)
            options.setdefault("MODE", "VERIFY")
        elif "web_deploy" in module.module_path or "53772" in module.module_path:
            options.setdefault("RPORT", 80)
            options.setdefault("SSL", False)
            options.setdefault("TARGETURI", "/MSDEPLOYAGENTSERVICE")
        elif "smb" in module.module_path:
            options.setdefault("RPORT", 445)
        elif "rdp" in module.module_path:
            options.setdefault("RPORT", 3389)

        rhost = options.get("RHOST") or options.get("RHOSTS") or "127.0.0.1"
        is_web_deploy = "web_deploy" in module.module_path or "53772" in module.module_path
        for name, required in module.required_options.items():
            if required and not options.get(name):
                if name == "LHOST":
                    options[name] = rhost  # LHOST = RHOST luôn
                elif name == "LPORT":
                    options[name] = 4444
                elif name == "USERNAME":
                    if is_web_deploy:
                        continue
                    options[name] = os.environ.get("USERNAME") or "Administrator"
                elif name == "PASSWORD":
                    if is_web_deploy:
                        continue
                    options[name] = "Password123"
                elif name in {"THREADS", "CONNECTIONS"}:
                    options[name] = 7000
                elif name == "STREAMS":
                    options[name] = 100
                elif name == "HEADERS":
                    options[name] = 900
                elif name == "HOLD":
                    options[name] = 300
                elif name == "DRIP":
                    options[name] = 5
                elif name == "POOL":
                    options[name] = 50


        missing = [name for name, required in module.required_options.items() if required and not options.get(name)]
        return options, missing


    def _severity(self, score):
        score = float(score or 0)
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"

    def _module_severity(self, status, score):
        if status == "completed":
            return self._severity(score)
        if status in {"failed", "timeout"}:
            return "medium"
        return "low"

    def _fail(self, scan, title, evidence):
        scan.score = 25
        scan.update_status("FAILED")
        self.repository.update_scan(scan)
        self.repository.save_cve_findings([CveFinding(self.repository.new_id(), scan.scan_id, evidence, "high", affected_service=title, risk_score=25, patch_status="Run the app with Administrator privileges and try again.")])
        self.job_service.update_status(scan.scan_id, status="FAILED", stage="Failed", percent=100)
