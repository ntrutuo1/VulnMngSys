class HistoryController:
    def __init__(self, scan_repository):
        self.scan_repository = scan_repository

    def handle_list_history(self, limit: int):
        return 200, self.scan_repository.list_scans(limit)

    def handle_delete_history(self, scan_id: str):
        self.scan_repository.delete_scan(scan_id)
        return 200, {"ok": True}
