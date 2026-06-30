from ..models.exceptions import NotFoundException, ValidationException


class ScanView:
    def __init__(self, scan_controller):
        self.scan_controller = scan_controller

    def post_services_scan(self, body: dict):
        try:
            target = body.get("target")
            res = self.scan_controller.start_service_scan(target, body)
            return 202, res
        except ValidationException as e:
            return 400, {"error": str(e)}
        except Exception as e:
            return 500, {"error": str(e)}

    def post_cis_audit(self, body: dict):
        try:
            target = body.get("target")
            benchmark = body.get("benchmark")
            res = self.scan_controller.start_cis_audit(target, benchmark)
            return 202, res
        except ValidationException as e:
            return 400, {"error": str(e)}
        except Exception as e:
            return 500, {"error": str(e)}

    def get_scan(self, scan_id: str):
        try:
            res = self.scan_controller.get_scan(scan_id)
            return 200, res
        except NotFoundException as e:
            return 404, {"error": str(e)}
        except Exception as e:
            return 500, {"error": str(e)}
