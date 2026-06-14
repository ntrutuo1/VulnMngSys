from __future__ import annotations

import json
import os
import re
from ipaddress import ip_address
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
from infrastructure.logging.system_logger import logger

from .api_helpers import error_response, is_action_allowed, json_response, read_json_body, server_error_response

_MSF_REPORT_PATH = Path(__file__).resolve().parents[2] / "reports" / "iis_msf_audit_report.json"
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")


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
    if not is_action_allowed(handler, "msf_audit"):
        error_response(handler, 403, "ACTION_NOT_ALLOWED", "MSF audit action is not allowed.")
        return True
    body = read_json_body(handler)
    target = str(body.get("target") or "127.0.0.1").strip()
    active_test = bool(body.get("activeTest", False))
    ports = _parse_ports(body.get("ports"), default=None)
    selected_cves = _parse_cves(body.get("selectedCves") or body.get("cves"))
    target_error = _validate_msf_target(target, active_test=active_test)
    if target_error:
        error_response(handler, 400, "INVALID_TARGET", target_error)
        return True
    requested_modules = load_safe_modules(
        active_test=active_test,
        selected_cves=selected_cves,
        ports=ports,
    )
    requires_msf = any(module.get("check_method") != "local_only" for module in requested_modules)
    manager = get_msf_manager()
    if requires_msf:
        connected, message = manager.wait_until_connected()
        if not connected:
            error_response(handler, 503, "MSF_RPC_UNAVAILABLE", message)
            return True
    try:
        logger.info(
            "Starting focused IIS CVE audit. target=%s active_test=%s ports=%s cves=%s",
            target,
            active_test,
            ports,
            selected_cves,
        )
        payload = run_iis_msf_audit(
            target=target,
            msfrpc_host=manager.config.host,
            msfrpc_port=manager.config.port,
            msfrpc_password=manager.config.password,
            msfrpc_ssl=manager.config.ssl,
            active_test=active_test,
            ports=ports,
            selected_cves=selected_cves,
        )
        payload["reportFile"] = str(write_json_report(payload))
        payload["htmlReportFile"] = str(write_html_report(payload))
        json_response(handler, 200, payload)
    except Exception as exc:
        logger.exception("MSF audit API failed: %s", exc)
        server_error_response(handler, "MSF_AUDIT_FAILED")
    return True


def _validate_msf_target(target: str, *, active_test: bool) -> str:
    if not target:
        return "Target is required."
    if any(char.isspace() for char in target) or len(target) > 253:
        return "Target must be a valid IP address or hostname."

    try:
        parsed_ip = ip_address(target)
    except ValueError:
        if not _HOSTNAME_RE.match(target) or ".." in target:
            return "Target must be a valid IP address or hostname."
        if active_test and target.casefold() != "localhost" and not os.getenv("VULNMNGSYS_ALLOW_REMOTE_MSF_ACTIVE_TEST"):
            return "Active MSF tests are limited to localhost or private IP targets by default."
        return ""

    active_override = os.getenv("VULNMNGSYS_ALLOW_REMOTE_MSF_ACTIVE_TEST")
    if active_test and not (parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_link_local or active_override):
        return "Active MSF tests are limited to localhost or private IP targets by default."
    return ""


def _parse_ports(value: object, *, default: list[int] | None) -> list[int] | None:
    if value is None:
        return default
    raw_items = value if isinstance(value, list) else [value]
    ports: list[int] = []
    for item in raw_items:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def _parse_cves(value: object) -> list[str] | None:
    if value is None:
        return None
    raw_items = value if isinstance(value, list) else [value]
    cves = []
    for item in raw_items:
        cve = str(item or "").strip().upper()
        if cve and cve.startswith("CVE-") and cve not in cves:
            cves.append(cve)
    return cves


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
        logger.exception("MSF modules API failed: %s", exc)
        server_error_response(handler, "MSF_MODULES_FAILED", "Unable to load MSF modules.")
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
        logger.exception("MSF report API failed: %s", exc)
        server_error_response(handler, "MSF_REPORT_FAILED", "Unable to load MSF report.")
    return True
