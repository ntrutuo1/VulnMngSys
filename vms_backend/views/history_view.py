from ..models.exceptions import NotFoundException, ValidationException


class HistoryView:
    def __init__(self, history_controller):
        self.history_controller = history_controller

    def get_list(self, query_params: dict):
        try:
            limit_str = query_params.get("limit", ["20"])[0]
            limit = min(int(limit_str), 100)
        except (ValueError, IndexError):
            limit = 20
        res = self.history_controller.list_history(limit)
        return 200, res

    def delete_item(self, scan_id: str):
        try:
            res = self.history_controller.delete_history(scan_id)
            return 200, res
        except NotFoundException as e:
            return 404, {"error": str(e)}
        except Exception as e:
            return 500, {"error": str(e)}
