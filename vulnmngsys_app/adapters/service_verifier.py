import subprocess
from typing import Dict, List

from vulnmngsys_app.adapters.logging.system_logger import logger

CRITICAL_SERVICES = ["W3SVC", "MSSQLSERVER"]


class ServiceVerifier:
    """Verify critical Windows services after reconfiguration."""

    def get_services_status(self, service_names: List[str] = CRITICAL_SERVICES) -> Dict[str, str]:
        statuses = {}
        for svc in service_names:
            try:
                result = subprocess.run(
                    [
                        "powershell",
                        "-Command",
                        f"(Get-Service -Name {svc} -ErrorAction SilentlyContinue).Status",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                statuses[svc] = result.stdout.strip() or "NotFound"
            except Exception as exc:
                logger.error("Failed to check service %s status: %s", svc, exc)
                statuses[svc] = "Error"
        return statuses

    def verify_after_fix(self, pre_fix_status: Dict[str, str]) -> bool:
        post_fix_status = self.get_services_status(list(pre_fix_status.keys()))
        stable = True

        for svc, before in pre_fix_status.items():
            after = post_fix_status.get(svc, "Unknown")
            logger.debug("Service %s: Before=%s, After=%s", svc, before, after)

            if before == "Running" and after != "Running":
                logger.critical("Critical service stopped after fix: %s", svc)
                stable = False

        return stable


service_verifier = ServiceVerifier()
