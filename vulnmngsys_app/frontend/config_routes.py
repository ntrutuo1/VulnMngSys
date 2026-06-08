from __future__ import annotations

from http.server import BaseHTTPRequestHandler

from app_bootstrap.scanflow.inventory import load_windows_inventory
from app_bootstrap.scanflow.reconfig import generate_reconfig_script, run_reconfig_script
from app_bootstrap.scanflow.views.scan_backend_view import (
    SCAN_FEATURE_MESSAGE,
    get_scan_backend_view,
    load_report_file,
    run_scan_and_save_report,
)
from infrastructure.logging.system_logger import logger

from .api_helpers import error_response, is_action_allowed, json_response, read_json_body, server_error_response


def handle_config_get(handler: BaseHTTPRequestHandler, path: str) -> bool:
    if path == "/api/status":
        json_response(handler, 200, {"ok": True, "service": "VulnMngSys Desktop API"})
        return True
    if path == "/api/inventory":
        return _inventory(handler)
    if path in {"/api/report", "/api/report/export"}:
        return _report(handler)
    return False


def handle_config_post(handler: BaseHTTPRequestHandler, path: str) -> bool:
    if path == "/api/reconfig":
        return _reconfig(handler)
    if path != "/api/scan":
        return False
    if not is_action_allowed(handler, "scan"):
        error_response(handler, 403, "ACTION_NOT_ALLOWED", "Scan action is not allowed.")
        return True
    body = read_json_body(handler)
    profile_key = body.get("profileKey") or body.get("profile_key")
    mode = str(body.get("mode") or "quick").strip().lower()
    full_scan = bool(body.get("fullScan") if "fullScan" in body else mode == "full")
    try:
        payload = run_scan_and_save_report(
            profile_key=profile_key,
            mode="full" if full_scan else "quick",
        )
        json_response(handler, 200, payload)
    except Exception as exc:
        logger.exception("Scan API failed: %s", exc)
        server_error_response(handler, "SCAN_FAILED", SCAN_FEATURE_MESSAGE)
    return True


def _reconfig(handler: BaseHTTPRequestHandler) -> bool:
    try:
        body = read_json_body(handler)
        selected_rule_ids = body.get("selectedRuleIds")
        selected_rule_ids = selected_rule_ids if isinstance(selected_rule_ids, list) else None
        view = get_scan_backend_view()
        report = view.load_report_file()
        if body.get("apply") is True:
            if not is_action_allowed(handler, "apply_reconfig"):
                error_response(handler, 403, "ACTION_NOT_ALLOWED", "Apply reconfig action is not allowed.")
                return True
            payload = run_reconfig_script(report, view.app_root(), selected_rule_ids=selected_rule_ids)
        else:
            if not is_action_allowed(handler, "preview_reconfig"):
                error_response(handler, 403, "ACTION_NOT_ALLOWED", "Preview reconfig action is not allowed.")
                return True
            payload = {
                "ok": True,
                "requiresReview": True,
                **generate_reconfig_script(report, view.app_root(), selected_rule_ids=selected_rule_ids),
            }
        json_response(handler, 200 if payload.get("ok") else 500, payload)
    except Exception as exc:
        logger.exception("Reconfig API failed: %s", exc)
        server_error_response(handler, "RECONFIG_FAILED")
    return True


def _inventory(handler: BaseHTTPRequestHandler) -> bool:
    try:
        inv = load_windows_inventory()
        json_response(handler, 200, {"ok": True, "inventory": _inventory_payload(inv)})
    except Exception as exc:
        logger.exception("Inventory API failed: %s", exc)
        server_error_response(handler, "INVENTORY_FAILED", "Unable to load machine inventory.")
    return True


def _inventory_payload(inv) -> dict[str, object]:
    return {
        "computerName": inv.computer_name,
        "osCaption": inv.os_caption,
        "osVersion": inv.os_version,
        "buildNumber": inv.build_number,
        "productType": inv.product_type,
        "isServer": inv.is_server,
        "profileKey": inv.profile_key,
    }


def _report(handler: BaseHTTPRequestHandler) -> bool:
    try:
        json_response(handler, 200, load_report_file())
    except Exception as exc:
        logger.exception("Report API failed: %s", exc)
        error_response(handler, 503, "REPORT_UNAVAILABLE", SCAN_FEATURE_MESSAGE)
    return True
