import os
import socket
from ..config import MSFRPC_HOST, MSFRPC_PORT


class StatusView:
    def __init__(self, application):
        self.application = application

    def get_status(self):
        try:
            lan_ip = "127.0.0.1"
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.connect(("8.8.8.8", 80))
                    host = sock.getsockname()[0]
                    if host and not host.startswith("127."):
                        lan_ip = host
            except OSError:
                try:
                    host = socket.gethostbyname(socket.gethostname())
                    if host and not host.startswith("127."):
                        lan_ip = host
                except OSError:
                    pass

            return 200, {
                "ready": True,
                "lan_ip": lan_ip,
                "backend_host": os.environ.get("VMS_HOST", ""),
                "msf_available": self.application.msf_available,
                "msf_path": self.application.msf_path,
                "msfrpcd_available": self.application.msfrpcd_available,
                "msfrpcd_path": self.application.msfrpcd_path,
                "msfrpc_host": MSFRPC_HOST,
                "msfrpc_port": MSFRPC_PORT,
            }
        except Exception as e:
            return 500, {"error": str(e)}

