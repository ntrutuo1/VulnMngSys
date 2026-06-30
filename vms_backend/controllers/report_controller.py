from ..models.exceptions import NotFoundException


class ReportController:
    def __init__(self, report_service):
        self.report_service = report_service

    def get_report(self, scan_id: str):
        report = self.report_service.get_report(scan_id)
        if not report:
            raise NotFoundException("Report not found")
        return report
