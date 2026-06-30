from vms_backend.services.scan_service import ScanService
from vms_backend.services.metasploit_engine import MetasploitEngine


class FakeRepository:
    def new_id(self):
        return "id"


def demo():
    services = [{"Name": "RemoteRegistry", "DisplayName": "Remote Registry", "Status": "Running"}]
    ports = [{"LocalPort": 23, "State": "Listen"}]
    software = [{"DisplayName": "Apache HTTP Server", "DisplayVersion": "2.2.34"}]
    engine = MetasploitEngine(FakeRepository(), None, None, None)
    findings = engine.evaluate_services("scan-1", services, ports, software)
    assert len(findings) == 3
    scan_service = ScanService(None, None, None, None)
    assert scan_service.validate_target("localhost") == "localhost"
    try:
        scan_service.validate_target("localhost; rm")
    except ValueError:
        pass
    else:
        raise AssertionError("shell metacharacters must be rejected")


if __name__ == "__main__":
    demo()
    print("ok")
