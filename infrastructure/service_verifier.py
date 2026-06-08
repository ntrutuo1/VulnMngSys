import subprocess
from typing import Dict, List
from infrastructure.logging.system_logger import logger

CRITICAL_SERVICES = ["W3SVC", "MSSQLSERVER"]

class ServiceVerifier:
    """Kiểm tra và đảm bảo các Service quan trọng không bị chết sau khi Reconfig."""

    def __init__(self):
        pass

    def get_services_status(self, service_names: List[str] = CRITICAL_SERVICES) -> Dict[str, str]:
        """Lấy trạng thái hiện tại của danh sách các service."""
        statuses = {}
        for svc in service_names:
            try:
                # Chạy Get-Service qua PowerShell
                result = subprocess.run(
                    ["powershell", "-Command", f"(Get-Service -Name {svc} -ErrorAction SilentlyContinue).Status"],
                    capture_output=True, text=True, timeout=30
                )
                status = result.stdout.strip()
                if status:
                    statuses[svc] = status
                else:
                    statuses[svc] = "NotFound"
            except Exception as e:
                logger.error(f"Lỗi khi kiểm tra trạng thái service {svc}: {e}")
                statuses[svc] = "Error"
        return statuses

    def verify_after_fix(self, pre_fix_status: Dict[str, str]) -> bool:
        """
        Kiểm tra lại sau khi fix.
        Trả về True nếu hệ thống ổn định, False nếu có service quan trọng bị Crash (từ Running -> Stopped).
        """
        post_fix_status = self.get_services_status(list(pre_fix_status.keys()))
        stable = True

        for svc, before in pre_fix_status.items():
            after = post_fix_status.get(svc, "Unknown")
            logger.debug(f"Service {svc}: Before={before}, After={after}")
            
            if before == "Running" and after != "Running":
                logger.critical(f"PHÁT HIỆN LỖI NGHIÊM TRỌNG: Dịch vụ {svc} đã bị ngưng hoạt động sau khi chạy Fix!")
                stable = False

        return stable

service_verifier = ServiceVerifier()
