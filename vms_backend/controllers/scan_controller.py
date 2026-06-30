class ScanController:
    def __init__(self, scan_service, report_service, job_service):
        self.scan_service = scan_service
        self.report_service = report_service
        self.job_service = job_service

    def handle_service_scan(self, body: dict):
        return 202, {"scanId": self.scan_service.start_service_scan(body.get("target", "localhost"))}

    def handle_cis_audit(self, body: dict):
        return 202, {"scanId": self.scan_service.start_cis_scan(body.get("target", "localhost"))}

    def handle_get_scan(self, scan_id: str):
        report = self.report_service.get_report(scan_id)
        if not report:
            return 404, {"error": "not_found"}
        report["job"] = self.job_service.get_status(scan_id)
        return 200, report
