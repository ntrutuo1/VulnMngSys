from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from app_bootstrap.scanflow.msf_audit.audit_runner import run_iis_msf_audit
from app_bootstrap.scanflow.msf_audit.metasploit_manager import get_msf_manager
from app_bootstrap.scanflow.msf_audit.module_loader import (
    load_excluded_modules,
    load_profile_metadata,
    load_safe_modules,
)
from app_bootstrap.scanflow.msf_audit.report_writer import write_html_report, write_json_report

from .api_helpers import json_response, read_json_body

_MSF_REPORT_PATH = Path(__file__).resolve().parents[2] / "reports" / "iis_msf_audit_report.json"


def start_msf_runtime() -> None:
    get_msf_manager().ensure_async()


def handle_msf_get(handler: BaseHTTPRequestHandler, path: str, query: str) -> bool:
    if path == "/api/msf/status":
        json_response(handler, 200, get_msf_manager().status())
        return True
    if path == "/api/msf/modules":
        return _modules(handler, query)
    if path == "/api/msf/report":
        return _report(handler)
    return False


def handle_msf_post(handler: BaseHTTPRequestHandler, path: str) -> bool:
    if path != "/api/msf/audit":
        return False
    body = read_json_body(handler)
    target = str(body.get("target") or "127.0.0.1").strip()
    active_test = bool(body.get("activeTest", False))
    manager = get_msf_manager()
    connected, message = manager.wait_until_connected()
    if not connected:
        json_response(handler, 503, {"ok": False, "error": message})
        return True
    try:
        payload = run_iis_msf_audit(
            target=target,
            msfrpc_host=manager.config.host,
            msfrpc_port=manager.config.port,
            msfrpc_password=manager.config.password,
            msfrpc_ssl=manager.config.ssl,
            active_test=active_test,
        )
        payload["reportFile"] = str(write_json_report(payload))
        payload["htmlReportFile"] = str(write_html_report(payload))
        json_response(handler, 200, payload)
    except Exception as exc:
        json_response(handler, 500, {"ok": False, "error": str(exc)})
    return True


def _modules(handler: BaseHTTPRequestHandler, query: str) -> bool:
    try:
        active_test = "active_test=true" in query.lower()
        modules = load_safe_modules(active_test=active_test)
        json_response(
            handler,
            200,
            {
                "ok": True,
                "modules": modules,
                "excluded": load_excluded_modules(),
                "metadata": load_profile_metadata(),
                "total": len(modules),
            },
        )
    except Exception as exc:
        json_response(handler, 500, {"ok": False, "error": str(exc)})
    return True


def _report(handler: BaseHTTPRequestHandler) -> bool:
    try:
        if not _MSF_REPORT_PATH.exists():
            json_response(handler, 404, {"ok": False, "error": "No MSF audit report found. Run an audit first."})
            return True
        payload = json.loads(_MSF_REPORT_PATH.read_text(encoding="utf-8"))
        payload.setdefault("ok", True)
        json_response(handler, 200, payload)
    except Exception as exc:
        json_response(handler, 500, {"ok": False, "error": str(exc)})
    return True
