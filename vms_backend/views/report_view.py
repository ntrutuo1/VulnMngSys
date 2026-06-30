from ..models.exceptions import NotFoundException


class ReportView:
    def __init__(self, report_controller):
        self.report_controller = report_controller

    def get_report(self, scan_id: str):
        try:
            res = self.report_controller.get_report(scan_id)
            return 200, res
        except NotFoundException as e:
            return 404, {"error": str(e)}
        except Exception as e:
            return 500, {"error": str(e)}
