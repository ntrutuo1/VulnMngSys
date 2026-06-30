class ReportService:
    def __init__(self, scan_repository):
        self.scan_repository = scan_repository

    def get_report(self, scan_id: str):
        scan = self.scan_repository.find_scan(scan_id)
        if not scan:
            return None
        return {"scan": scan, "findings": self.scan_repository.list_findings(scan_id)}
