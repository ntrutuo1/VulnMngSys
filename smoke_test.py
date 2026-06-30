from vms_backend.services.scan_service import ScanService
from vms_backend.services.metasploit_engine import MetasploitEngine
from vms_backend.services.cis_audit_engine import CisAuditEngine
from vms_backend.models import CisRule, MetasploitModuleSpec


class FakeRepository:
    def new_id(self):
        return "id"


class FakePowerShell:
    def __init__(self, output):
        self.output = output

    def execute_cmd(self, script, timeout=20):
        return self.output


class FakeCveRepository:
    def find_for_services(self, service_names):
        return []


def demo():
    services = [{"Name": "RemoteRegistry", "DisplayName": "Remote Registry", "Status": "Running"}]
    ports = [{"LocalPort": 23, "State": "Listen"}]
    software = [{"DisplayName": "Apache HTTP Server", "DisplayVersion": "2.2.34"}]
    engine = MetasploitEngine(FakeRepository(), FakeCveRepository(), None, None, None)
    findings = engine.evaluate_services("scan-1", services, ports, software)
    assert len(findings) == 3
    module = MetasploitModuleSpec("CVE-2026-49975", "auxiliary/customs/cve_2026_49975_http2_bomb", "auxiliary", "x.rb", {"RHOSTS": True, "RPORT": True, "MODE": True}, {"MODE": "VERIFY"})
    options, missing = engine.build_module_options(module, {"services": {"http2"}, "ports": {443}})
    assert not missing and options["MODE"] == "VERIFY" and options["SSL"] is True
    scan_service = ScanService(None, None, None, None)
    assert scan_service.validate_target("localhost") == "localhost"
    try:
        scan_service.validate_target("localhost; rm")
    except ValueError:
        pass
    else:
        raise AssertionError("shell metacharacters must be rejected")
    rule = CisRule("h", "CIS-WIN2025", "x.json", "1.1", "Test", "echo 1", "1")
    assert CisAuditEngine(None, None, None, FakePowerShell("1")).evaluate_rule(rule) == (True, "1")
    assert CisAuditEngine(None, None, None, FakePowerShell("")).evaluate_rule(rule) is None


if __name__ == "__main__":
    demo()
    print("ok")
