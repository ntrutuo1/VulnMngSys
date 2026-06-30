import re
import threading

from ..models import ScanHistory, TargetServer


class ScanService:
    def __init__(self, repository, job_service, cis_engine, metasploit_engine):
        self.repository = repository
        self.job_service = job_service
        self.cis_engine = cis_engine
        self.metasploit_engine = metasploit_engine

    def start_service_scan(self, target: str, scan_options: dict = None):
        return self._start_scan("services", target, self.metasploit_engine.run_vulnerability_scan, scan_options)

    def start_cis_scan(self, target: str, benchmark: str | None = None):
        return self._start_scan("cis", target, self.cis_engine.run_config_audit, benchmark)

    def _start_scan(self, scan_type: str, target: str, runner, *runner_args):
        target = self.validate_target(target)
        target_server = TargetServer(target_id=self.repository.new_id(), ip_address=target)
        scan = ScanHistory(scan_id=self.repository.new_id(), target_id=target_server.target_id, status="RUNNING", scan_type=scan_type)
        self.repository.save_target(target_server)
        self.repository.create_scan(scan)
        self.job_service.update_status(scan.scan_id, status="RUNNING", stage="Queued", percent=5)
        threading.Thread(target=runner, args=(scan, *runner_args), daemon=True).start()
        return scan.scan_id

    def validate_target(self, value: str):
        value = (value or "localhost").strip()
        if len(value) > 120 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
            raise ValueError("Invalid target")
        return value
