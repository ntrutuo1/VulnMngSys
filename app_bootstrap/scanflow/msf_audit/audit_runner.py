"""Orchestrator: run full IIS MSF audit and return structured payload."""
from __future__ import annotations

import datetime
from typing import Any

from .module_loader import load_safe_modules, load_profile_metadata
from .msfrpc_runner import MsfRpcRunner, MsfRpcConnectionError
from .result_analyzer import analyze
from .score_calculator import calculate_score, score_label, score_color


def run_iis_msf_audit(
    *,
    target: str = "127.0.0.1",
    msfrpc_host: str = "127.0.0.1",
    msfrpc_port: int = 55552,
    msfrpc_password: str = "",
    msfrpc_ssl: bool = True,
    active_test: bool = False,
) -> dict[str, Any]:
    """Run all safe IIS Metasploit modules and return a report payload.

    Args:
        target: IP/hostname of the IIS server to scan.
        msfrpc_host: msfrpc server address.
        msfrpc_port: msfrpc port (default 55552).
        msfrpc_password: msfrpc password.
        msfrpc_ssl: Use SSL for msfrpc connection.
        active_test: If True, include conditional modules (http_put_write_test).

    Returns:
        dict payload ready to be serialized to JSON or returned via API.
    """
    runner = MsfRpcRunner(
        host=msfrpc_host,
        port=msfrpc_port,
        password=msfrpc_password,
        ssl=msfrpc_ssl,
    )

    modules = load_safe_modules(active_test=active_test)
    metadata = load_profile_metadata()
    results: list[dict[str, Any]] = []

    for mod in modules:
        module_id = mod.get("id", "")
        display_id = mod.get("display_id", module_id)
        module_path = mod.get("module", "")
        safe_to_run = mod.get("safe_to_run", True)

        # SKIPPED modules (conditional, active_test off)
        if safe_to_run == "conditional" and not active_test:
            results.append(_skipped_result(mod, display_id))
            continue

        # Run each local_variant (HTTP + HTTPS, etc.)
        variant_results: list[dict[str, Any]] = []
        for variant in mod.get("local_variants", [{}]):
            datastore = dict(mod.get("default_datastore", {}))
            datastore.update(variant)
            datastore["RHOSTS"] = target

            try:
                raw_output = runner.run_module(module_path, datastore)
                analysis = analyze(mod, raw_output)
            except MsfRpcConnectionError as exc:
                analysis = {
                    "status": "ERROR",
                    "evidence": f"msfrpc connection error: {exc}",
                    "remediation": "Verify Metasploit Framework is running with msfRPC.",
                }
            except Exception as exc:
                analysis = {
                    "status": "ERROR",
                    "evidence": f"Module execution error: {exc}",
                    "remediation": "Check module options and target connectivity.",
                }

            variant_results.append(
                {
                    "port": datastore.get("RPORT", 80),
                    "ssl": bool(datastore.get("SSL", False)),
                    **analysis,
                }
            )

        # Merge variant results: worst status wins
        merged = _merge_variant_results(mod, display_id, variant_results)
        results.append(merged)

    # Calculate score
    score = calculate_score(results)

    # Build summary counters
    summary = _build_summary(results)

    return {
        "ok": True,
        "profile": metadata.get("profile_name", ""),
        "target": target,
        "service": "IIS / HTTP.sys",
        "scan_mode": "active" if active_test else "safe",
        "active_test": active_test,
        "timestamp": datetime.datetime.now().isoformat(),
        "score": score,
        "score_label": score_label(score),
        "score_color": score_color(score),
        "summary": summary,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_STATUS_RANK: dict[str, int] = {
    "ERROR": 5,
    "FAIL": 4,
    "WARNING": 3,
    "INFO": 2,
    "SKIPPED": 1,
    "PASS": 0,
}


def _merge_variant_results(
    mod: dict[str, Any],
    display_id: str,
    variant_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Combine HTTP + HTTPS variant results, taking the worst status."""
    if not variant_results:
        return _skipped_result(mod, display_id)

    # Sort by status severity, pick worst
    worst = max(variant_results, key=lambda r: _STATUS_RANK.get(r.get("status", "PASS"), 0))

    return {
        "id": display_id,
        "module_id": mod.get("id", ""),
        "module": mod.get("module", ""),
        "name": mod.get("name", ""),
        "category": mod.get("category", ""),
        "risk": mod.get("risk", ""),
        "cve": mod.get("cve", []),
        "port": worst.get("port", 80),
        "ssl": worst.get("ssl", False),
        "status": worst.get("status", "PASS"),
        "evidence": worst.get("evidence", ""),
        "remediation": worst.get("remediation", ""),
        "server_2022_relevance": mod.get("server_2022_relevance", ""),
        "expected_signal": mod.get("expected_signal", ""),
    }


def _skipped_result(mod: dict[str, Any], display_id: str) -> dict[str, Any]:
    return {
        "id": display_id,
        "module_id": mod.get("id", ""),
        "module": mod.get("module", ""),
        "name": mod.get("name", ""),
        "category": mod.get("category", ""),
        "risk": mod.get("risk", ""),
        "cve": mod.get("cve", []),
        "port": mod.get("default_datastore", {}).get("RPORT", 80),
        "ssl": False,
        "status": "SKIPPED",
        "evidence": "Skipped: active test mode not enabled",
        "remediation": "Enable active test mode to run this check.",
        "server_2022_relevance": mod.get("server_2022_relevance", ""),
        "expected_signal": mod.get("expected_signal", ""),
    }


def _build_summary(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {
        "pass": 0,
        "fail": 0,
        "warning": 0,
        "info": 0,
        "skipped": 0,
        "error": 0,
    }
    for r in results:
        key = r.get("status", "").lower()
        if key in counts:
            counts[key] += 1
    return counts
