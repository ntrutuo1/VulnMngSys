import argparse
import json
import os
import socket
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .adapters import MsfRpcAdapter, PowerShellAdapter
from .config import MSFCONSOLE_PATH, MSFRPCD_PATH, MSFRPC_HOST, MSFRPC_PORT, WEB_DIR
from .controllers import DashboardController, HistoryController, ReportController, ScanController, SystemController
from .database import SQLiteDatabase
from .repositories import CisRuleRepository, CveRepository, ScanRepository, StatRepository, SystemRepository
from .services import CisAuditEngine, DashboardService, JobService, MetasploitEngine, ReportService, ScanService, SystemService


class Application:
    def __init__(self):
        self.database = SQLiteDatabase()
        self.database.initialize()
        self.msf_available = MSFCONSOLE_PATH.exists()
        self.msf_path = str(MSFCONSOLE_PATH)
        self.msfrpcd_available = MSFRPCD_PATH.exists()
        self.msfrpcd_path = str(MSFRPCD_PATH)
        powershell = PowerShellAdapter()
        scan_repository = ScanRepository(self.database)
        import threading
        
        rule_repository = CisRuleRepository(self.database)
        cve_repository = CveRepository(self.database)
        
        def background_init():
            try:
                rule_repository.import_from_files()
                cve_repository.import_dataset()
            except Exception as e:
                print("Failed background database initialization:", e, flush=True)
                
        threading.Thread(target=background_init, daemon=True).start()
        
        self.rule_repository = rule_repository
        job_service = JobService()
        cis_engine = CisAuditEngine(scan_repository, rule_repository, job_service, powershell)
        metasploit_engine = MetasploitEngine(scan_repository, cve_repository, job_service, powershell, MsfRpcAdapter())
        report_service = ReportService(scan_repository)
        self.scan_controller = ScanController(ScanService(scan_repository, job_service, cis_engine, metasploit_engine), report_service, job_service)
        self.history_controller = HistoryController(scan_repository)
        self.report_controller = ReportController(report_service)
        self.dashboard_controller = DashboardController(DashboardService(StatRepository(self.database)))
        self.system_controller = SystemController(SystemService(SystemRepository(powershell)))


def create_handler(application: Application):
    class ApiHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(WEB_DIR), **kwargs)

        def end_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def send_json(self, status_code: int, payload):
            body = json.dumps(payload).encode()
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def read_json(self):
            size = min(int(self.headers.get("Content-Length", "0")), 65536)
            return json.loads(self.rfile.read(size) or b"{}")

        def do_GET(self):
            parsed = urlparse(self.path)
            if not parsed.path.startswith("/api/"):
                return super().do_GET()
            try:
                status, payload = self.route_get(parsed)
                self.send_json(status, payload)
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})

        def do_POST(self):
            try:
                body = self.read_json()
                if self.path == "/api/scans/services":
                    status, payload = application.scan_controller.handle_service_scan(body)
                elif self.path == "/api/scans/cis":
                    status, payload = application.scan_controller.handle_cis_audit(body)
                else:
                    status, payload = 404, {"error": "not_found"}
                self.send_json(status, payload)
            except ValueError as exc:
                self.send_json(400, {"error": str(exc)})
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})

        def do_DELETE(self):
            if not self.path.startswith("/api/scans/"):
                return self.send_json(404, {"error": "not_found"})
            status, payload = application.history_controller.handle_delete_history(self.path.split("/")[-1])
            self.send_json(status, payload)

        def route_get(self, parsed):
            if parsed.path == "/api/system/info":
                return application.system_controller.handle_get_system_info()
            if parsed.path == "/api/scans":
                limit = min(int(parse_qs(parsed.query).get("limit", ["20"])[0]), 100)
                return application.history_controller.handle_list_history(limit)
            if parsed.path.startswith("/api/scans/"):
                return application.scan_controller.handle_get_scan(parsed.path.split("/")[-1])
            if parsed.path.startswith("/api/reports/"):
                return application.report_controller.handle_get_report(parsed.path.split("/")[-1])
            if parsed.path == "/api/stats/dashboard":
                return application.dashboard_controller.handle_get_dashboard()
            if parsed.path == "/api/cis/benchmarks":
                return 200, application.rule_repository.list_benchmarks()
            if parsed.path == "/api/status":
                return 200, {
                    "ready": True,
                    "backend_host": os.environ.get("VMS_HOST", ""),
                    "msf_available": application.msf_available,
                    "msf_path": application.msf_path,
                    "msfrpcd_available": application.msfrpcd_available,
                    "msfrpcd_path": application.msfrpcd_path,
                    "msfrpc_host": MSFRPC_HOST,
                    "msfrpc_port": MSFRPC_PORT,
                }
            return 404, {"error": "not_found"}

    return ApiHandler


def get_default_host():
    env_host = os.environ.get("VMS_HOST")
    if env_host:
        return env_host
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            host = sock.getsockname()[0]
            if host and not host.startswith("127."):
                return host
    except OSError:
        pass
    try:
        host = socket.gethostbyname(socket.gethostname())
        if host and not host.startswith("127."):
            return host
    except OSError:
        pass
    return "127.0.0.1"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=get_default_host())
    parser.add_argument("--port", type=int, default=int(os.environ.get("VMS_PORT", "8765")))
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), create_handler(Application()))
    print(f"http://{args.host}:{args.port}", flush=True)
    server.serve_forever()
