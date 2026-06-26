from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from vulnmngsys_app.services.iis_audit import (
    apply_iis_reconfigure,
    backupandRollback,
    cancelServiceScan,
    generateConfigScanReport,
    getServiceScanStatus,
    getOSInfo,
    preview_iis_reconfigure,
    reconfigure,
    sanitizeServiceReport,
    scanConfiguration,
    scanService,
)
from vulnmngsys_app.services.scanflow.paths import writable_reports_dir

from .api_helpers import error_response, is_action_allowed, json_response, read_json_body, server_error_response

_IIS_REPORT_PATH = writable_reports_dir() / "iis_msf_audit_report.json"


def handle_iis_get(handler: BaseHTTPRequestHandler, path: str, query: str = "") -> bool:
    if path == "/api/iis/os-info":
        json_response(handler, 200, getOSInfo())
        return True
    if path == "/api/iis/scan/service/status":
        json_response(handler, 200, getServiceScanStatus())
        return True
    if path.startswith("/api/iis/reports/"):
        return _report(handler, path)
    return False


def handle_iis_post(handler: BaseHTTPRequestHandler, path: str) -> bool:
    if path == "/api/iis/scan/configuration":
        return _scan_configuration(handler)
    if path == "/api/iis/scan/cve":
        return _scan_cve(handler)
    if path == "/api/iis/scan/service":
        return _scan_cve(handler)
    if path == "/api/iis/scan/service/cancel":
        return _cancel_service_scan(handler)
    if path == "/api/iis/scan/full":
        return _scan_full(handler)
    if path == "/api/iis/reconfigure/preview":
        return _reconfigure(handler, apply=False)
    if path == "/api/iis/reconfigure/apply":
        return _reconfigure(handler, apply=True)
    if path == "/api/iis/rollback":
        return _rollback(handler)
    return False


def _scan_configuration(handler: BaseHTTPRequestHandler) -> bool:
    if not is_action_allowed(handler, "scan"):
        error_response(handler, 403, "ACTION_NOT_ALLOWED", "Scan action is not allowed.")
        return True
    body = read_json_body(handler)
    try:
        payload = scanConfiguration(
            profile_key=body.get("profileKey") or body.get("profile_key"),
            mode=str(body.get("mode") or "quick").lower(),
            scan_id=str(body.get("scanId") or body.get("scan_id") or ""),
        )
        json_response(handler, 200, payload)
    except Exception as exc:
        server_error_response(handler, "SCAN_FAILED", str(exc) or "Configuration scan failed.")
    return True


def _scan_cve(handler: BaseHTTPRequestHandler) -> bool:
    if not is_action_allowed(handler, "msf_audit"):
        error_response(handler, 403, "ACTION_NOT_ALLOWED", "MSF audit action is not allowed.")
        return True
    body = read_json_body(handler)
    try:
        payload = scanService(
            target=str(body.get("target") or "127.0.0.1").strip(),
            active_test=bool(body.get("activeTest", False)),
            ports=_parse_ports(body.get("ports")),
            services=_parse_services(body.get("services") or body.get("service")),
            selected_cves=_parse_cves(body.get("selectedCves") or body.get("cves")),
        )
        json_response(handler, 200 if payload.get("ok") else 500, payload)
    except Exception as exc:
        server_error_response(handler, "MSF_AUDIT_FAILED", str(exc) or "IIS CVE scan failed.")
    return True


def _cancel_service_scan(handler: BaseHTTPRequestHandler) -> bool:
    if not is_action_allowed(handler, "msf_audit"):
        error_response(handler, 403, "ACTION_NOT_ALLOWED", "MSF audit action is not allowed.")
        return True
    json_response(handler, 200, cancelServiceScan())
    return True


def _scan_full(handler: BaseHTTPRequestHandler) -> bool:
    if not is_action_allowed(handler, "scan") or not is_action_allowed(handler, "msf_audit"):
        error_response(handler, 403, "ACTION_NOT_ALLOWED", "Full IIS scan action is not allowed.")
        return True
    body = read_json_body(handler)
    config = scanConfiguration(
        profile_key=body.get("profileKey") or body.get("profile_key"),
        mode=str(body.get("mode") or "quick").lower(),
        scan_id=str(body.get("scanId") or body.get("scan_id") or ""),
    )
    cve = scanService(
        target=str(body.get("target") or "127.0.0.1").strip(),
        active_test=bool(body.get("activeTest", False)),
        ports=_parse_ports(body.get("ports")),
        services=_parse_services(body.get("services") or body.get("service")),
        selected_cves=_parse_cves(body.get("selectedCves") or body.get("cves")),
    )
    json_response(handler, 200, {"ok": bool(config.get("ok") and cve.get("ok")), "configuration": config, "cve": cve})
    return True


def _reconfigure(handler: BaseHTTPRequestHandler, *, apply: bool) -> bool:
    if not is_action_allowed(handler, "apply_reconfig" if apply else "preview_reconfig"):
        error_response(handler, 403, "ACTION_NOT_ALLOWED", "Reconfigure action is not allowed.")
        return True
    body = read_json_body(handler)
    selected_rule_ids = body.get("selectedRuleIds")
    selected_rule_ids = selected_rule_ids if isinstance(selected_rule_ids, list) else []
    try:
        if body.get("scope") == "iis_cve":
            report = json.loads(_IIS_REPORT_PATH.read_text(encoding="utf-8"))
            selected_cves = _parse_cves(body.get("selectedCves") or body.get("cves"))
            app_root = Path(__file__).resolve().parents[2]
            payload = (
                apply_iis_reconfigure(report, app_root, selected_cves, confirmed=bool(body.get("confirmed")))
                if apply
                else preview_iis_reconfigure(report, app_root, selected_cves)
            )
        else:
            report = generateConfigScanReport()
            app_root = Path(__file__).resolve().parents[2]
            payload = reconfigure(
                report=report,
                app_root=app_root,
                selected_rule_ids=[str(item) for item in selected_rule_ids],
                apply=apply,
                confirmed=bool(body.get("confirmed")),
            )
        json_response(handler, 200 if payload.get("ok") else 500, payload)
    except FileNotFoundError:
        error_response(handler, 404, "REPORT_UNAVAILABLE", "Run scan before reconfigure.")
    except Exception as exc:
        server_error_response(handler, "RECONFIGURE_FAILED", str(exc) or "Reconfigure failed.")
    return True


def _rollback(handler: BaseHTTPRequestHandler) -> bool:
    body = read_json_body(handler)
    payload = backupandRollback(action="rollback", backup_id=str(body.get("backupId") or body.get("backup_id") or ""))
    json_response(handler, 200 if payload.get("ok") else 500, payload)
    return True


def _report(handler: BaseHTTPRequestHandler, path: str) -> bool:
    report_id = path.rsplit("/", 1)[-1]
    candidates = {
        "config": writable_reports_dir() / "scan_compare_report.json",
        "iis": _IIS_REPORT_PATH,
    }
    report_path = candidates.get(report_id)
    if not report_path or not report_path.exists():
        error_response(handler, 404, "REPORT_UNAVAILABLE", "Report not found.")
        return True
    payload = json.loads(report_path.read_text(encoding="utf-8-sig"))
    if report_id == "iis":
        payload = sanitizeServiceReport(payload)
    json_response(handler, 200, payload)
    return True


def _parse_ports(value: object) -> list[int] | None:
    if value is None:
        return None
    ports = []
    for item in value if isinstance(value, list) else [value]:
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
    cves = []
    for item in value if isinstance(value, list) else [value]:
        cve = str(item or "").strip().upper()
        if cve.startswith("CVE-") and cve not in cves:
            cves.append(cve)
    return cves


def _parse_services(value: object) -> list[str] | None:
    if value is None:
        return None
    services = []
    for item in value if isinstance(value, list) else [value]:
        service = str(item or "").strip().lower()
        if service and service not in services:
            services.append(service)
    return services
