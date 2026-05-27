from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from app_bootstrap.scanflow.inventory import load_windows_inventory
from app_bootstrap.scanflow.service_id_map import valid_service_ids
from ..scan_backend import SCAN_FEATURE_MESSAGE, load_report_file, run_scan_and_save_report


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    handler.end_headers()
    handler.wfile.write(raw)


def create_api_server(host: str = "127.0.0.1", port: int = 5000) -> tuple[ThreadingHTTPServer, threading.Thread]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_OPTIONS(self) -> None:  # noqa: N802
            _json_response(self, 200, {"ok": True})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)

            if parsed.path == "/api/status":
                _json_response(self, 200, {"ok": True, "service": "VulnMngSys Desktop API"})
                return

            if parsed.path == "/api/inventory":
                try:
                    inv = load_windows_inventory()
                    _json_response(
                        self,
                        200,
                        {
                            "ok": True,
                            "inventory": {
                                "computerName": inv.computer_name,
                                "osCaption": inv.os_caption,
                                "osVersion": inv.os_version,
                                "isServer": inv.is_server,
                                "profileKey": inv.profile_key,
                                "detectedServiceCount": inv.detected_service_count,
                                "detectedServices": inv.detected_services,
                            },
                        },
                    )
                except Exception as exc:
                    _json_response(self, 500, {"ok": False, "error": str(exc)})
                return

            if parsed.path == "/api/report":
                try:
                    payload = load_report_file()
                    _json_response(self, 200, payload)
                except Exception as exc:
                    _json_response(self, 503, {"ok": False, "error": str(exc) or SCAN_FEATURE_MESSAGE})
                return

            if parsed.path == "/api/report/export":
                try:
                    payload = load_report_file()
                    _json_response(self, 200, payload)
                except Exception as exc:
                    _json_response(self, 503, {"ok": False, "error": str(exc) or SCAN_FEATURE_MESSAGE})
                return

            _json_response(self, 404, {"ok": False, "error": "Not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/api/scan":
                _json_response(self, 404, {"ok": False, "error": "Not found"})
                return

            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(length).decode("utf-8") if length else "{}"
                body = json.loads(raw_body or "{}")
            except Exception:
                body = {}

            profile_key = body.get("profileKey") or body.get("profile_key")
            mode = str(body.get("mode") or "quick").strip().lower()
            full_scan = bool(body.get("fullScan") if "fullScan" in body else mode == "full")
            selected_services_raw = body.get("selectedServices") or body.get("selected_service_names") or []
            selected_service_names = {
                str(item).strip()
                for item in selected_services_raw
                if str(item).strip()
            }
            selected_service_ids_raw = body.get("selectedServiceIds") or body.get("selected_service_ids") or []
            selected_service_ids: set[int] = set()
            invalid_ids: list[str] = []

            for item in selected_service_ids_raw:
                try:
                    selected_service_ids.add(int(str(item).strip()))
                except Exception:
                    invalid_ids.append(str(item))

            known_ids = valid_service_ids()
            unknown_ids = sorted(service_id for service_id in selected_service_ids if service_id not in known_ids)
            if invalid_ids or unknown_ids:
                _json_response(
                    self,
                    400,
                    {
                        "ok": False,
                        "error": "Invalid selectedServiceIds",
                        "invalidIds": invalid_ids,
                        "unknownIds": unknown_ids,
                    },
                )
                return

            try:
                payload = run_scan_and_save_report(
                    profile_key=profile_key,
                    mode="full" if full_scan else "quick",
                    selected_service_names=selected_service_names,
                    selected_service_ids=selected_service_ids,
                )
                _json_response(self, 200, payload)
            except Exception as exc:
                _json_response(self, 500, {"ok": False, "error": str(exc) or SCAN_FEATURE_MESSAGE})

    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="vulnmngsys-api", daemon=True)
    return server, thread
