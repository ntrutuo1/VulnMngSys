from __future__ import annotations

import http.server
import io
import json
import socketserver
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ...infrastructure.platform.service_probe import (
    detect_host_family,
    detect_host_version,
    list_service_versions,
)
from ...scanner import scan_module
from ...modules import load_modules


class FrontendNotFoundError(FileNotFoundError):
    pass


def _scan_report_to_dict(report) -> dict:
    """Convert ScanReport dataclass to JSON-serializable dict."""
    return {
        "module": {
            "module_id": report.module.module_id,
            "os_family": report.module.os_family,
            "os_version": report.module.os_version,
            "service_type": report.module.service_type,
            "display_name": report.module.display_name,
            "rules_source_file": report.module.rules_source_file,
        },
        "used_config_paths": report.used_config_paths,
        "summary": {
            "total_checks": report.summary.total_checks,
            "passed_checks": report.summary.passed_checks,
            "failed_checks": report.summary.failed_checks,
            "hardening_index": report.summary.hardening_index,
            "grade": report.summary.grade,
            "warnings": report.summary.warnings,
        },
        "results": [
            {
                "code": r.code,
                "title": r.title,
                "severity": r.severity,
                "weight": r.weight,
                "passed": r.passed,
                "reason": r.reason,
                "config_path": r.config_path,
                "config_line": r.config_line,
                "baseline": r.baseline,
                "explanation": r.explanation,
                "actual_line": r.actual_line,
                "suggested_line": r.suggested_line,
            }
            for r in report.results
        ],
        "version_context": report.version_context,
        "cve_advisories": [
            {
                "cve_id": c.cve_id,
                "title": c.title,
                "severity": c.severity,
                "likelihood": c.likelihood,
                "reason": c.reason,
                "reference": c.reference,
            }
            for c in report.cve_advisories
        ],
    }


def resolve_frontend_dir() -> Path:
    candidates: list[Path] = []

    if getattr(sys, "frozen", False):
        base_dir = Path(sys._MEIPASS)
        candidates.extend(
            [
                base_dir / "react-ui" / "dist",
                base_dir / "dist",
            ]
        )
    else:
        project_root = Path(__file__).resolve().parents[3]
        candidates.extend(
            [
                project_root / "react-ui" / "dist",
                project_root / "dist",
            ]
        )

    for candidate in candidates:
        index_file = candidate / "index.html"
        if index_file.exists():
            return candidate

    raise FrontendNotFoundError("React frontend build not found. Run npm run build in react-ui first.")


@contextmanager
def _serve_directory(directory: Path, port: int = 0):
    class FrontendHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(directory), **kwargs)

        def _write_json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/api/detect/host":
                self._write_json(
                    {
                        "osFamily": detect_host_family(),
                        "osVersion": detect_host_version(),
                    }
                )
                return

            if parsed.path == "/api/detect/service":
                query = parse_qs(parsed.query)
                service_type = (query.get("type") or [""])[0].strip()
                apache_layout = (query.get("layout") or ["auto"])[0].strip().lower() or "auto"
                xampp_root = (query.get("xamppRoot") or [""])[0].strip() or None
                if service_type not in {"ssh", "apache-http", "apache-tomcat"}:
                    self._write_json({"error": "Invalid service type"}, status=400)
                    return
                if apache_layout not in {"auto", "xampp", "standalone"}:
                    self._write_json({"error": "Invalid apache layout"}, status=400)
                    return

                hits = list_service_versions(
                    service_type,
                    apache_layout=apache_layout,
                    xampp_root=xampp_root,
                )

                self._write_json(
                    {
                        "service": service_type,
                        "apacheLayout": apache_layout,
                        "xamppRoot": xampp_root or "",
                        "serviceVersion": hits[0]["version"] if hits else "",
                        "hits": hits,
                    }
                )
                return

            return super().do_GET()

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path == "/api/scan":
                try:
                    content_length = int(self.headers.get("Content-Length", 0))
                    if content_length == 0:
                        self._write_json({"error": "Empty request body"}, status=400)
                        return

                    body = self.rfile.read(content_length)
                    payload = json.loads(body.decode("utf-8"))

                    module_id = payload.get("module_id", "").strip()
                    os_version = payload.get("os_version", "").strip() or None
                    service_version = payload.get("service_version", "").strip() or None
                    xampp_version = payload.get("xampp_version", "").strip() or None
                    xampp_root = payload.get("xampp_root", "").strip() or None

                    if not module_id:
                        self._write_json({"error": "module_id is required"}, status=400)
                        return

                    # Find the module from catalog
                    modules = load_modules()
                    module = None
                    for m in modules:
                        if m.module_id == module_id:
                            module = m
                            break

                    if not module:
                        self._write_json({"error": f"Module {module_id} not found"}, status=404)
                        return

                    # Run the actual scan with optional xampp_root
                    report = scan_module(
                        module,
                        os_version=os_version,
                        service_version=service_version,
                        xampp_version=xampp_version,
                        xampp_root=xampp_root,
                    )

                    # Convert report to JSON-serializable format
                    result = _scan_report_to_dict(report)
                    self._write_json(result)

                except json.JSONDecodeError:
                    self._write_json({"error": "Invalid JSON in request body"}, status=400)
                except FileNotFoundError as e:
                    self._write_json({"error": f"Configuration file not found: {str(e)}"}, status=404)
                except Exception as e:
                    self._write_json({"error": f"Scan error: {str(e)}"}, status=500)
                return

            return super().do_GET()

    handler = FrontendHandler
    with socketserver.ThreadingTCPServer(("127.0.0.1", port), handler) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=1)


def launch_react_frontend(open_browser: bool = True) -> None:
    frontend_dir = resolve_frontend_dir()
    with _serve_directory(frontend_dir) as port:
        url = f"http://127.0.0.1:{port}/"
        if open_browser:
            _launch_firefox_view(url)
            return

        try:
            import webview
        except ModuleNotFoundError:
            raise

        webview.create_window(
            title="VulnMngSys Desktop Scanner",
            url=url,
            width=1440,
            height=960,
            min_size=(1100, 760),
            background_color="#0b1020",
            resizable=True,
        )
        webview.start(debug=False)


def _launch_firefox_view(url: str) -> None:
    commands = [
        ["firefox", "--new-window", "--kiosk", url],
        ["firefox", "--new-window", url],
    ]

    for command in commands:
        try:
            proc = subprocess.Popen(command)
        except OSError:
            continue

        try:
            proc.wait()
        finally:
            time.sleep(0.2)
        return

    raise RuntimeError("Firefox is not available. Install firefox or use --legacy-ui.")
