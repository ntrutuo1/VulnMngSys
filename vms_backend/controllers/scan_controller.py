from ..models.exceptions import NotFoundException, ValidationException


class ScanController:
    def __init__(self, scan_service, report_service, job_service):
        self.scan_service = scan_service
        self.report_service = report_service
        self.job_service = job_service

    def start_service_scan(self, target: str, scan_options: dict = None):
        if not target:
            raise ValidationException("Target host is required")
        scan_id = self.scan_service.start_service_scan(target, scan_options or {})
        return {"scanId": scan_id}

    def start_cis_audit(self, target: str, benchmark: str = None):
        if not target:
            raise ValidationException("Target host is required")
        scan_id = self.scan_service.start_cis_scan(target, benchmark)
        return {"scanId": scan_id}

    def get_scan(self, scan_id: str):
        report = self.report_service.get_report(scan_id)
        if not report:
            raise NotFoundException("Scan report not found")
        report["job"] = self.job_service.get_status(scan_id)
        return report
