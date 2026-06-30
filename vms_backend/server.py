import argparse
import json
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .adapters import MsfRpcAdapter, PowerShellAdapter
from .config import WEB_DIR
from .controllers import DashboardController, HistoryController, ReportController, ScanController, SystemController
from .database import SQLiteDatabase
from .repositories import ScanRepository, StatRepository, SystemRepository
from .services import CisAuditEngine, DashboardService, JobService, MetasploitEngine, ReportService, ScanService, SystemService


class Application:
    def __init__(self):
        self.database = SQLiteDatabase()
        self.database.initialize()
        powershell = PowerShellAdapter()
        scan_repository = ScanRepository(self.database)
        job_service = JobService()
        cis_engine = CisAuditEngine(scan_repository, job_service, powershell)
        metasploit_engine = MetasploitEngine(scan_repository, job_service, powershell, MsfRpcAdapter())
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
            return 404, {"error": "not_found"}

    return ApiHandler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.environ.get("VMS_PORT", "8765")))
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), create_handler(Application()))
    print(f"http://127.0.0.1:{args.port}", flush=True)
    server.serve_forever()
