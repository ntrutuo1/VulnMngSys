class ReportController:
    def __init__(self, report_service):
        self.report_service = report_service

    def handle_get_report(self, scan_id: str):
        report = self.report_service.get_report(scan_id)
        return (200, report) if report else (404, {"error": "not_found"})
