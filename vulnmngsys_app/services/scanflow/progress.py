from __future__ import annotations

import threading
from datetime import datetime
from typing import Any


_LOCK = threading.Lock()
_SCAN_PROGRESS: dict[str, dict[str, Any]] = {}
_MAX_RECENT_RULES = 30


def start_scan_progress(scan_id: str, *, profile_key: str, full_scan: bool, total: int) -> None:
    if not scan_id:
        return
    now = _now()
    with _LOCK:
        _SCAN_PROGRESS[scan_id] = {
            "ok": True,
            "scanId": scan_id,
            "status": "running",
            "profileKey": profile_key,
            "fullScan": full_scan,
            "total": total,
            "completed": 0,
            "percent": 0,
            "currentRule": None,
            "recentRules": [],
            "error": "",
            "startedAt": now,
            "updatedAt": now,
        }


def mark_rule_started(scan_id: str, rule: Any, *, index: int, total: int) -> None:
    if not scan_id:
        return
    with _LOCK:
        payload = _SCAN_PROGRESS.setdefault(scan_id, _base_payload(scan_id))
        payload.update(
            {
                "status": "running",
                "total": total,
                "completed": max(index - 1, 0),
                "percent": _percent(max(index - 1, 0), total),
                "currentRule": _rule_payload(rule, status="RUNNING"),
                "updatedAt": _now(),
            }
        )


def mark_rule_finished(scan_id: str, rule: Any, *, index: int, total: int, result: Any) -> None:
    if not scan_id:
        return
    row = _rule_payload(rule, status=_result_status(result))
    with _LOCK:
        payload = _SCAN_PROGRESS.setdefault(scan_id, _base_payload(scan_id))
        recent = [row, *(payload.get("recentRules") or [])][:_MAX_RECENT_RULES]
        payload.update(
            {
                "status": "running",
                "total": total,
                "completed": index,
                "percent": _percent(index, total),
                "currentRule": row,
                "recentRules": recent,
                "updatedAt": _now(),
            }
        )


def complete_scan_progress(scan_id: str) -> None:
    if not scan_id:
        return
    with _LOCK:
        payload = _SCAN_PROGRESS.setdefault(scan_id, _base_payload(scan_id))
        total = int(payload.get("total") or 0)
        payload.update(
            {
                "status": "completed",
                "completed": total,
                "percent": 100 if total else 0,
                "currentRule": None,
                "updatedAt": _now(),
            }
        )


def fail_scan_progress(scan_id: str, error: str) -> None:
    if not scan_id:
        return
    with _LOCK:
        payload = _SCAN_PROGRESS.setdefault(scan_id, _base_payload(scan_id))
        payload.update(
            {
                "status": "failed",
                "error": str(error or "Scan failed."),
                "currentRule": None,
                "updatedAt": _now(),
            }
        )


def get_scan_progress(scan_id: str) -> dict[str, Any]:
    with _LOCK:
        payload = dict(_SCAN_PROGRESS.get(scan_id) or _base_payload(scan_id))
        payload["ok"] = True
        return payload


def _base_payload(scan_id: str) -> dict[str, Any]:
    return {
        "ok": True,
        "scanId": scan_id,
        "status": "idle",
        "profileKey": "",
        "fullScan": False,
        "total": 0,
        "completed": 0,
        "percent": 0,
        "currentRule": None,
        "recentRules": [],
        "error": "",
        "startedAt": "",
        "updatedAt": _now(),
    }


def _rule_payload(rule: Any, *, status: str) -> dict[str, Any]:
    raw = getattr(rule, "raw_spec", None) or {}
    return {
        "ruleId": str(getattr(rule, "id", "") or raw.get("id") or ""),
        "title": str(getattr(rule, "title", "") or raw.get("title") or ""),
        "service": str(getattr(rule, "service", "") or raw.get("service") or ""),
        "hash_id": str(raw.get("hash_id") or ""),
        "status": status,
    }


def _result_status(result: Any) -> str:
    return str(getattr(result, "verdict", "") or "DONE").upper()


def _percent(completed: int, total: int) -> int:
    if total <= 0:
        return 0
    return max(0, min(100, round((completed / total) * 100)))


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")
