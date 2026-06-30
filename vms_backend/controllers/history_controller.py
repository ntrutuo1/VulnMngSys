class HistoryController:
    def __init__(self, scan_repository):
        self.scan_repository = scan_repository

    def list_history(self, limit: int):
        return self.scan_repository.list_scans(limit)

    def delete_history(self, scan_id: str):
        self.scan_repository.delete_scan(scan_id)
        return {"ok": True}
