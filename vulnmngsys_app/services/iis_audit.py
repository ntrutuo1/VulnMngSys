from __future__ import annotations

import concurrent.futures
import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

from vulnmngsys_app.adapters.backup_manager import backup_manager
from vulnmngsys_app.services.scan_facade import load_report_file, run_scan_and_save_report
from vulnmngsys_app.services.scanflow.inventory import load_windows_inventory
from vulnmngsys_app.services.scanflow.msf_audit.audit_runner import run_iis_msf_audit, run_local_patch_check
from vulnmngsys_app.services.scanflow.msf_audit.metasploit_manager import get_msf_manager
from vulnmngsys_app.services.scanflow.msf_audit.msfrpc_runner import MsfRpcRunner
from vulnmngsys_app.services.scanflow.msf_audit.module_loader import load_cve_modules, load_profile_metadata
from vulnmngsys_app.services.scanflow.msf_audit.report_writer import write_html_report, write_json_report
from vulnmngsys_app.services.scanflow.msf_audit.score_calculator import calculate_score, calculate_dread_details
from vulnmngsys_app.startup.dependencies import iis_remediation_pipeline, remediation_pipeline

SERVICE_COMPONENTS = {
    "all": {"*"},
    "iis": {"IIS_CORE", "HTTP_SYS", "WEBDAV", "WEBDEPLOY", "WSUS"},
    "active_directory": {"ACTIVE_DIRECTORY", "AD_CS"},
    "exchange": {"EXCHANGE"},
    "mssql": {"MSSQL"},
    "rdp": {"RDP"},
    "smb": {"SMB"},
    "winrm": {"WINRM"},
    "windows": {"WINDOWS_HOST", "PRINT_SPOOLER"},
}
SERVICE_DEFAULT_DATASTORE = {
    "IIS_CORE": {"RPORT": 80, "SSL": False},
    "HTTP_SYS": {"RPORT": 80, "SSL": False},
    "WEBDAV": {"RPORT": 80, "SSL": False},
    "WEBDEPLOY": {"RPORT": 8172, "SSL": True},
    "WSUS": {"RPORT": 8530, "SSL": False},
    "SMB": {"RPORT": 445, "SSL": False},
    "RDP": {"RPORT": 3389, "SSL": False},
    "WINRM": {"RPORT": 5985, "SSL": False},
    "EXCHANGE": {"RPORT": 443, "SSL": True},
    "MSSQL": {"RPORT": 1433, "SSL": False},
    "AD_CS": {"RPORT": 80, "SSL": False},
    "ACTIVE_DIRECTORY": {"RPORT": 389, "SSL": False},
}
SERVICE_CATEGORY_KEYWORDS = {
    "iis": {"iis", "httpsys", "webdav", "webdeploy", "wsus"},
    "active_directory": {"netlogon", "adcs", "certificate"},
    "exchange": {"exchange"},
    "mssql": {"mssql", "ssrs", "sqlserver"},
    "rdp": {"rdp"},
    "smb": {"smb", "smbv3"},
    "winrm": {"winrm"},
    "windows": {"httpsys", "msmq", "print", "netlogon", "adcs", "smb", "smbv3", "rdp"},
}
_service_scan_lock = threading.Lock()
_service_scan_cancel = threading.Event()
_service_scan_running = False
_MSF_CHECK_TIMEOUT = 30.0
NON_WINDOWS_MODULE_PREFIXES = (
    "exploit/aix/",
    "exploit/bsdi/",
    "exploit/freebsd/",
    "exploit/linux/",
    "exploit/osx/",
    "exploit/solaris/",
    "exploit/unix/",
    "post/aix/",
    "post/bsdi/",
    "post/freebsd/",
    "post/linux/",
    "post/osx/",
    "post/solaris/",
    "post/unix/",
)


@dataclass
class OSInfoCollector:
    def collect(self) -> dict[str, Any]:
        try:
            inv = load_windows_inventory()
            return {
                "ok": True,
                "status": "OK",
                "admin": None,
                "os": {
                    "name": inv.os_caption,
                    "edition": "UNKNOWN",
                    "displayVersion": "UNKNOWN",
                    "currentBuild": inv.build_number,
                    "ubr": "UNKNOWN",
                    "fullBuild": inv.build_number,
                    "version": inv.os_version,
                    "productType": inv.product_type,
                    "isServer": inv.is_server,
                    "profileKey": inv.profile_key,
                },
                "patches": [],
                "iis": {
                    "installed": None,
                    "version": "UNKNOWN",
                    "appcmdAvailable": None,
                    "services": [],
                    "features": [],
                },
                "errors": [],
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": "UNKNOWN",
                "errors": [_error("POWERSHELL_FAILED", str(exc) or "Khong thu thap duoc OS info.")],
            }


@dataclass
class ConfigurationScanService:
    def scan(self, *, profile_key: str | None = None, mode: str = "quick", scan_id: str = "") -> dict[str, Any]:
        return run_scan_and_save_report(profile_key=profile_key, mode=mode, scan_id=scan_id)


@dataclass
class AuditReportService:
    def generate_config_report(self, report_file: Path | None = None) -> dict[str, Any]:
        try:
            return load_report_file(report_file)
        except Exception as exc:
            return {
                "ok": False,
                "code": "REPORT_GENERATION_FAILED",
                "error": str(exc) or "Khong doc duoc bao cao cau hinh.",
            }

    def generate_iis_report(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            payload["reportFile"] = str(write_json_report(payload))
            payload["htmlReportFile"] = str(write_html_report(payload))
            payload.setdefault("ok", True)
            return payload
        except Exception as exc:
            return {
                "ok": False,
                "code": "REPORT_GENERATION_FAILED",
                "error": str(exc) or "Khong sinh duoc bao cao IIS.",
                "payload": payload,
            }


@dataclass
class BackupRollbackUseCase:
    backup: Any = backup_manager

    def run(
        self,
        *,
        action: str = "create",
        backup_id: str = "",
        reason: str = "",
        selected_rules: Iterable[str] | None = None,
        registry_paths: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        if action == "rollback":
            return self._rollback(backup_id)
        return self._create(reason=reason, selected_rules=selected_rules, registry_paths=registry_paths)

    def _create(
        self,
        *,
        reason: str,
        selected_rules: Iterable[str] | None,
        registry_paths: Iterable[str] | None,
    ) -> dict[str, Any]:
        backup_id = self.backup.createBackup(
            reason=reason,
            selectedRules=list(selected_rules or []),
            registryPaths=list(registry_paths or []),
        )
        verified = self.backup.verifyBackup(backup_id)
        return {
            "ok": verified,
            "status": "READY" if verified else "FAILED",
            "backupId": backup_id,
            "backupPath": str(self.backup.backup_path(backup_id)),
            "verified": verified,
        }

    def _rollback(self, backup_id: str) -> dict[str, Any]:
        if not backup_id:
            return {"ok": False, "status": "FAILED", "code": "BACKUP_FAILED", "error": "backupId is required."}
        rolled_back = self.backup.rollback(backup_id)
        verified = self.backup.verifyRollback(backup_id)
        return {
            "ok": rolled_back and verified,
            "status": "ROLLED_BACK" if rolled_back and verified else "MANUAL_RECOVERY_REQUIRED",
            "backupId": backup_id,
            "rollbackVerified": verified,
        }


@dataclass
class ReconfigureUseCase:
    def run(
        self,
        *,
        report: dict[str, Any],
        app_root: Path,
        selected_rule_ids: list[str] | None,
        apply: bool = False,
        confirmed: bool = False,
    ) -> dict[str, Any]:
        if apply and not confirmed:
            return {"ok": False, "status": "CANCELLED", "code": "CONFIRMATION_REQUIRED"}
        if apply and not selected_rule_ids:
            return {"ok": False, "status": "FAILED", "code": "RECONFIGURE_PLAN_UNSAFE", "error": "No selected rule."}

        pipeline = remediation_pipeline()
        payload = (
            pipeline.apply(report, app_root, selected_rule_ids)
            if apply
            else pipeline.preview(report, app_root, selected_rule_ids)
        )
        return _normalize_reconfigure_payload(payload, apply=apply)


@dataclass
class ServiceCveScanUseCase:
    report_service: AuditReportService

    def scan(
        self,
        *,
        target: str = "127.0.0.1",
        active_test: bool = False,
        ports: Iterable[int] | None = None,
        services: Iterable[str] | None = None,
        selected_cves: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        _begin_service_scan()
        legacy_cve_mode = bool(selected_cves) and services is None
        try:
            selected_services = _normalize_services(services) or ["iis"]
            modules = self._modules_for_services(selected_services, selected_cves=selected_cves)
            if not modules and selected_cves:
                modules = load_cve_modules(selected_cves=selected_cves, ports=ports)
            manager = get_msf_manager()
            msf_available = self._msf_available(modules, manager)

            if legacy_cve_mode and msf_available:
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
            elif legacy_cve_mode:
                return {
                    "ok": False,
                    "code": "MSFRPC_UNAVAILABLE",
                    "error": "Metasploit RPC is required because Service Scan must execute module checks.",
                }
            else:
                if not msf_available:
                    return {
                        "ok": False,
                        "code": "MSFRPC_UNAVAILABLE",
                        "error": "Metasploit RPC is required because Service Scan must execute module checks.",
                        "service": ", ".join(selected_services),
                        "moduleCount": len(modules),
                    }
                payload = self._service_scan_payload(
                    target=target,
                    modules=modules,
                    services=selected_services,
                    selected_cves=selected_cves,
                    msf_available=msf_available,
                    active_test=True,
                )

            return self.report_service.generate_iis_report(payload)
        finally:
            _finish_service_scan()

    def _msf_available(self, modules: list[dict[str, Any]], manager: Any) -> bool:
        if not any(_module_requires_msf(module) for module in modules):
            return True
        available, _ = manager.wait_until_connected()
        return bool(available)

    def _modules_for_services(
        self,
        services: list[str],
        *,
        selected_cves: Iterable[str] | None,
    ) -> list[dict[str, Any]]:
        modules = [module for module in _load_warehouse_service_modules(services) if _is_windows_service_module(module)]
        selected = {str(cve).strip().upper() for cve in selected_cves or [] if str(cve).strip()}
        if selected:
            modules = [module for module in modules if selected.intersection(set(module.get("cves", [])))]
        return modules

    def _service_scan_payload(
        self,
        *,
        target: str,
        modules: list[dict[str, Any]],
        services: list[str],
        selected_cves: Iterable[str] | None,
        msf_available: bool,
        active_test: bool,
    ) -> dict[str, Any]:
        results = []
        # Create one shared runner to reuse the MSFRPC connection across modules.
        shared_runner: MsfRpcRunner | None = None
        if msf_available:
            try:
                manager = get_msf_manager()
                shared_runner = MsfRpcRunner(
                    host=manager.config.host,
                    port=manager.config.port,
                    password=manager.config.password,
                    ssl=manager.config.ssl,
                )
            except Exception as exc:
                logger.warning("Failed to create shared MsfRpcRunner: %s", exc)

        for index, module in enumerate(modules, start=1):
            if _service_scan_cancel.is_set():
                break
            cves = [str(cve).upper() for cve in module.get("cves", []) if cve]
            check_supported = bool(module.get("check_supported", False))
            if _module_requires_msf(module):
                msf_results = [_run_safe_msf_check_timed(module, target, shared_runner)]
                status = msf_results[0]["status"]
                module_options = msf_results[0].get("datastore", {})
                evidence = msf_results[0].get("evidence") or "MSF module did not return evidence."
                local_result = {
                    "status": "INFO",
                    "evidence": "Local profile selected this module. PASS/FAIL evidence comes from MSF Checks.",
                }
                msf_state = "CHECK_EXECUTED"
            else:
                local_result = run_local_patch_check(
                    cves[0] if cves else "",
                    target=target,
                    config=module.get("local_check") or {},
                )
                status = _local_service_status(local_result)
                module_options = {}
                evidence = local_result.get("evidence") or "Local PowerShell check did not return evidence."
                msf_results = []
                msf_state = "LOCAL_ONLY"
            results.append(
                {
                    "id": f"SERVICE-MODULE-{index:04d}",
                    "module_id": module.get("fullname", ""),
                    "module": module.get("fullname", ""),
                    "module_type": module.get("module_type", ""),
                    "name": module.get("name", ""),
                    "cve": cves,
                    "severity": "UNKNOWN",
                    "status": status,
                    "serviceStatus": "CHECKED",
                    "confidence": _msf_confidence(status),
                    "evidence": evidence,
                    "remediation": "Review applicability on the selected service, install vendor patch if applicable, then rerun service scan.",
                    "components": module.get("components", []),
                    "references": module.get("references", []),
                    "check_supported": check_supported,
                    "module_options": module_options,
                    "option_source": module.get("default_datastore_source", "fallback"),
                    "check_command": "check" if module.get("module_type") == "exploit" else "run" if _module_requires_msf(module) else "local",
                    "check_executed": bool(msf_results[0].get("check_executed")) if msf_results else False,
                    "warehouse_source": module.get("warehouse_source", "windows_server_all_service_msf_modules_expanded.json"),
                    "local_check_result": local_result,
                    "msf_results": msf_results,
                    "msf_check_state": msf_state,
                }
            )
            _write_partial_service_report(
                _fallback_payload(
                    target=target,
                    results=results,
                    selected_cves=selected_cves,
                    services=services,
                    scan_status="RUNNING",
                    completed_modules=index,
                    total_modules=len(modules),
                )
            )
        return _fallback_payload(
            target=target,
            results=results,
            selected_cves=selected_cves,
            services=services,
            scan_status="CANCELLED" if _service_scan_cancel.is_set() else "COMPLETED",
            completed_modules=len(results),
            total_modules=len(modules),
        )

    def _local_fallback(
        self,
        *,
        target: str,
        modules: list[dict[str, Any]],
        selected_cves: Iterable[str] | None,
    ) -> dict[str, Any]:
        results = []
        for index, module in enumerate(modules, start=1):
            cves = [str(cve).upper() for cve in module.get("cve", []) if cve]
            local = run_local_patch_check(cves[0] if cves else "", target=target, config=module.get("local_check") or {})
            status = "PATCHED" if local.get("patch_found") else "UNKNOWN"
            if local.get("applicable") is False:
                status = "NOT_APPLICABLE"
            elif local.get("status") == "FAIL":
                status = "LIKELY"
            results.append(
                {
                    "id": module.get("display_id") or f"IIS-CVE-{index:03d}",
                    "module_id": module.get("id", ""),
                    "module": module.get("module", ""),
                    "name": module.get("name", ""),
                    "cve": cves,
                    "severity": module.get("severity", ""),
                    "status": status,
                    "evidence": local.get("evidence", "MSFRPC unavailable; local evidence only."),
                    "local_check_result": local,
                    "msf_results": [],
                }
            )
        return _fallback_payload(target=target, results=results, selected_cves=selected_cves)


@dataclass
class IISCveReconfigureUseCase:
    def preview(self, report: dict[str, Any], app_root: Path, selected_cves: list[str] | None) -> dict[str, Any]:
        return iis_remediation_pipeline().preview(report, app_root, selected_cves=selected_cves)

    def apply(
        self,
        report: dict[str, Any],
        app_root: Path,
        selected_cves: list[str] | None,
        *,
        confirmed: bool = False,
    ) -> dict[str, Any]:
        if not confirmed:
            return {"ok": False, "status": "CANCELLED", "code": "CONFIRMATION_REQUIRED"}
        if not selected_cves:
            return {"ok": False, "status": "FAILED", "code": "RECONFIGURE_PLAN_UNSAFE", "error": "No selected CVE."}
        return iis_remediation_pipeline().apply(report, app_root, selected_cves=selected_cves)


@dataclass
class IISAuditOrchestrator:
    os_collector: OSInfoCollector = field(default_factory=OSInfoCollector)
    configuration_scan: ConfigurationScanService = field(default_factory=ConfigurationScanService)
    report_service: AuditReportService = field(default_factory=AuditReportService)
    backup_rollback: BackupRollbackUseCase = field(default_factory=BackupRollbackUseCase)
    reconfigure_use_case: ReconfigureUseCase = field(default_factory=ReconfigureUseCase)
    service_cve_scan: ServiceCveScanUseCase | None = None
    iis_cve_reconfigure: IISCveReconfigureUseCase = field(default_factory=IISCveReconfigureUseCase)

    def __post_init__(self) -> None:
        if self.service_cve_scan is None:
            self.service_cve_scan = ServiceCveScanUseCase(self.report_service)

    def getOSInfo(self) -> dict[str, Any]:
        return self.os_collector.collect()

    def scanConfiguration(
        self,
        *,
        profile_key: str | None = None,
        mode: str = "quick",
        scan_id: str = "",
    ) -> dict[str, Any]:
        return self.configuration_scan.scan(profile_key=profile_key, mode=mode, scan_id=scan_id)

    def backupandRollback(self, **kwargs: Any) -> dict[str, Any]:
        return self.backup_rollback.run(**kwargs)

    def reconfigure(self, **kwargs: Any) -> dict[str, Any]:
        return self.reconfigure_use_case.run(**kwargs)

    def scanService(self, **kwargs: Any) -> dict[str, Any]:
        assert self.service_cve_scan is not None
        return self.service_cve_scan.scan(**kwargs)

    def scanServiceCVE(self, **kwargs: Any) -> dict[str, Any]:
        return self.scanService(**kwargs)

    def generateIISReport(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.report_service.generate_iis_report(payload)

    def generateConfigScanReport(self, report_file: Path | None = None) -> dict[str, Any]:
        return self.report_service.generate_config_report(report_file)

    def previewIISCveReconfigure(
        self,
        report: dict[str, Any],
        app_root: Path,
        selected_cves: list[str] | None,
    ) -> dict[str, Any]:
        return self.iis_cve_reconfigure.preview(report, app_root, selected_cves)

    def applyIISCveReconfigure(
        self,
        report: dict[str, Any],
        app_root: Path,
        selected_cves: list[str] | None,
        *,
        confirmed: bool = False,
    ) -> dict[str, Any]:
        return self.iis_cve_reconfigure.apply(report, app_root, selected_cves, confirmed=confirmed)


_orchestrator = IISAuditOrchestrator()


def getOSInfo() -> dict[str, Any]:
    return _orchestrator.getOSInfo()


def scanConfiguration(
    *,
    profile_key: str | None = None,
    mode: str = "quick",
    scan_id: str = "",
) -> dict[str, Any]:
    return _orchestrator.scanConfiguration(profile_key=profile_key, mode=mode, scan_id=scan_id)


def generateConfigScanReport(report_file: Path | None = None) -> dict[str, Any]:
    return _orchestrator.generateConfigScanReport(report_file)


def backupandRollback(**kwargs: Any) -> dict[str, Any]:
    return _orchestrator.backupandRollback(**kwargs)


def reconfigure(**kwargs: Any) -> dict[str, Any]:
    return _orchestrator.reconfigure(**kwargs)


def scanServiceCVE(**kwargs: Any) -> dict[str, Any]:
    return _orchestrator.scanServiceCVE(**kwargs)


def scanService(**kwargs: Any) -> dict[str, Any]:
    return _orchestrator.scanService(**kwargs)


def cancelServiceScan() -> dict[str, Any]:
    _service_scan_cancel.set()
    return {"ok": True, "scanStatus": "CANCELLING" if _service_scan_is_running() else "IDLE"}


def getServiceScanStatus() -> dict[str, Any]:
    return {
        "ok": True,
        "running": _service_scan_is_running(),
        "cancelRequested": _service_scan_cancel.is_set(),
    }


def generateIISReport(payload: dict[str, Any]) -> dict[str, Any]:
    return _orchestrator.generateIISReport(payload)


def preview_iis_reconfigure(report: dict[str, Any], app_root: Path, selected_cves: list[str] | None) -> dict[str, Any]:
    return _orchestrator.previewIISCveReconfigure(report, app_root, selected_cves)


def apply_iis_reconfigure(
    report: dict[str, Any],
    app_root: Path,
    selected_cves: list[str] | None,
    *,
    confirmed: bool = False,
) -> dict[str, Any]:
    return _orchestrator.applyIISCveReconfigure(report, app_root, selected_cves, confirmed=confirmed)


def sanitizeServiceReport(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(payload)
    results = [_normalize_service_row(row) for row in sanitized.get("results", []) if _is_windows_service_module(row)]
    summary, score = _service_summary_and_score(results)
    sanitized["results"] = results
    sanitized["summary"] = summary
    sanitized["score"] = score
    sanitized["score_label"] = "Service scan"
    sanitized["score_color"] = "red" if score < 60 else "orange" if score < 85 else "green"
    sanitized.setdefault("ok", True)
    return sanitized


def _normalize_service_row(row: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(row)
    msf_results = normalized.get("msf_results") or []
    if msf_results:
        first = msf_results[0] or {}
        normalized["evidence"] = first.get("evidence") or normalized.get("evidence") or "MSF check did not return evidence."
        normalized["status"] = first.get("status") or normalized.get("status")
        normalized["module_options"] = first.get("datastore") or normalized.get("module_options", {})
        normalized["check_executed"] = bool(first.get("check_executed", True))
        normalized["msf_check_state"] = "CHECK_EXECUTED"
        normalized["serviceStatus"] = "CHECKED"
        normalized["confidence"] = _msf_confidence(str(normalized.get("status") or ""))
    local = normalized.get("local_check_result")
    if isinstance(local, dict) and "warehouse" in str(local.get("evidence", "")).casefold():
        local = dict(local)
        local["evidence"] = "Warehouse only selected this module. PASS/FAIL evidence comes from MSF Checks."
        normalized["local_check_result"] = local
    return normalized


def _fallback_payload(
    *,
    target: str,
    results: list[dict[str, Any]],
    selected_cves: Iterable[str] | None,
    services: Iterable[str] | None = None,
    scan_status: str = "COMPLETED",
    completed_modules: int | None = None,
    total_modules: int | None = None,
) -> dict[str, Any]:
    summary, score = _service_summary_and_score(results)
    return {
        "ok": True,
        "profile": load_profile_metadata().get("profile_name", ""),
        "target": target,
        "service": ", ".join(services or ["iis"]),
        "scan_mode": "service_warehouse",
        "scanStatus": scan_status,
        "completedModules": len(results) if completed_modules is None else completed_modules,
        "totalModules": len(results) if total_modules is None else total_modules,
        "active_test": False,
        "selected_cves": [str(cve).upper() for cve in selected_cves or []],
        "score": score,
        "score_label": "Service scan",
        "score_color": "red" if score < 60 else "orange" if score < 85 else "green",
        "summary": summary,
        "kb_patch_summary": [],
        "results": results,
    }


def _begin_service_scan() -> None:
    global _service_scan_running
    with _service_scan_lock:
        _service_scan_cancel.clear()
        _service_scan_running = True


def _finish_service_scan() -> None:
    global _service_scan_running
    with _service_scan_lock:
        _service_scan_running = False


def _service_scan_is_running() -> bool:
    with _service_scan_lock:
        return _service_scan_running


def _write_partial_service_report(payload: dict[str, Any]) -> None:
    try:
        write_json_report(sanitizeServiceReport(payload))
    except Exception:
        pass


def _service_summary_and_score(results: list[dict[str, Any]]) -> tuple[dict[str, int], int]:
    summary = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for result in results:
        status = result.get("status", "PASS")
        orig_sev = result.get("severity", "INFO")
        dread = calculate_dread_details(status, orig_sev)
        result["dread_details"] = dread
        result["severity"] = dread["severity"].upper()
        summary[dread["severity"]] += 1
    score = calculate_score(results)
    return summary, score


def _load_warehouse_service_modules(services: list[str]) -> list[dict[str, Any]]:
    profile_path = Path(__file__).resolve().parents[2] / "metasploit_modules" / "windows_server_all_service_msf_modules_expanded.json"
    if profile_path.exists():
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        modules = [
            _normalize_service_profile_module(module, profile_path.name)
            for module in profile.get("modules", [])
            if module.get("safe_to_run") is True
        ]
        return [
            module for module in sorted(modules, key=lambda item: str(item.get("fullname", "")).casefold())
            if _module_matches_selected_services(module, services)
        ]

    catalog_path = Path(__file__).resolve().parents[2] / "metasploit_modules" / "warehouse" / "windows_server_msf_module_catalog.json"
    if not catalog_path.exists():
        return []
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    wanted_components = set().union(*(SERVICE_COMPONENTS.get(service, set()) for service in services))
    catalog_modules = [module for module in catalog.get("windows_server_cve_modules", []) if _is_windows_service_module(module)]
    if "*" in wanted_components:
        return sorted(catalog_modules, key=lambda item: str(item.get("fullname", "")).casefold())
    modules = []
    for module in catalog_modules:
        components = set(module.get("components", []))
        if wanted_components.intersection(components):
            modules.append(module)
    return sorted(modules, key=lambda item: str(item.get("fullname", "")).casefold())


def _normalize_service_profile_module(module: dict[str, Any], source_name: str) -> dict[str, Any]:
    normalized = dict(module)
    module_path = _normalize_msf_module_path(str(module.get("module") or ""))
    cves = [str(cve).upper() for cve in module.get("cve", []) if cve]
    module_type = _normalize_msf_module_type(str(module.get("module_type") or ""), module_path)
    local_check = module.get("local_check") or {}
    services = [str(service) for service in local_check.get("service_names", []) if service]
    category = str(module.get("category") or "")
    components = _service_components_from_profile(category, services, module_path)
    normalized.update(
        {
            "fullname": module_path,
            "module": module_path,
            "module_type": module_type,
            "cves": cves,
            "references": cves,
            "components": components,
            "autofilter_services": _autofilter_services_from_variants(module.get("local_variants", [])),
            "check_supported": module.get("check_method") != "local_only",
            "warehouse_source": source_name,
            "default_datastore_source": "profile",
        }
    )
    return normalized


def _normalize_msf_module_path(module_path: str) -> str:
    path = module_path.strip().strip("/")
    if path.startswith("exploits/"):
        return "exploit/" + path.removeprefix("exploits/")
    return path


def _normalize_msf_module_type(module_type: str, module_path: str) -> str:
    value = module_type.strip().casefold()
    if value in {"exploit", "exploits"} or module_path.startswith("exploit/"):
        return "exploit"
    if value == "auxiliary" or module_path.startswith("auxiliary/"):
        return "auxiliary"
    return "local"


def _service_components_from_profile(category: str, service_names: list[str], module_path: str) -> list[str]:
    text = " ".join([category, module_path, *service_names]).casefold()
    components: list[str] = []
    mappings = [
        ("IIS_CORE", ("iis", "w3svc")),
        ("HTTP_SYS", ("httpsys", "http.sys", "http")),
        ("WEBDEPLOY", ("webdeploy", "msdeploy", "wmsvc")),
        ("WSUS", ("wsus", "updateservices")),
        ("SMB", ("smb", "lanmanserver")),
        ("RDP", ("rdp", "termservice")),
        ("WINRM", ("winrm",)),
        ("EXCHANGE", ("exchange",)),
        ("MSSQL", ("mssql", "ssrs", "sqlserver", "reportserver")),
        ("AD_CS", ("adcs", "certsvc", "certificate")),
        ("ACTIVE_DIRECTORY", ("netlogon",)),
        ("PRINT_SPOOLER", ("print", "spooler")),
        ("MSMQ", ("msmq",)),
        ("SSH", ("ssh", "openssh")),
        ("MYSQL", ("mysql", "mariadb")),
        ("POSTGRESQL", ("postgres", "postgresql")),
        ("MONGODB", ("mongodb",)),
    ]
    for component, keywords in mappings:
        if any(keyword in text for keyword in keywords):
            components.append(component)
    return components or ["WINDOWS_HOST"]


def _autofilter_services_from_variants(variants: Any) -> list[str]:
    services: set[str] = set()
    for variant in variants or []:
        if not isinstance(variant, dict):
            continue
        try:
            port = int(variant.get("RPORT"))
        except (TypeError, ValueError):
            continue
        if port in {80, 443, 8172, 8530, 8531, 5985, 5986, 8080}:
            services.add("http" if port in {80, 8530, 5985, 8080} else "https")
        if port in {445, 139}:
            services.add("smb")
        if port == 3389:
            services.add("rdp")
        if port == 22:
            services.add("ssh")
    return sorted(services)


def _module_matches_selected_services(module: dict[str, Any], services: list[str]) -> bool:
    if "all" in services:
        return True
    category = str(module.get("category") or "").casefold()
    module_path = str(module.get("fullname") or "").casefold()
    local_check = module.get("local_check") or {}
    service_text = " ".join(str(item) for item in local_check.get("service_names", [])).casefold()
    components = {str(component).casefold() for component in module.get("components", [])}
    haystack = " ".join([category, module_path, service_text, " ".join(components)])
    for service in services:
        wanted_components = {item.casefold() for item in SERVICE_COMPONENTS.get(service, set())}
        if wanted_components.intersection(components):
            return True
        if any(keyword in haystack for keyword in SERVICE_CATEGORY_KEYWORDS.get(service, set())):
            return True
    return False


def _is_windows_service_module(module: dict[str, Any]) -> bool:
    fullname = str(module.get("fullname") or module.get("module") or module.get("module_id") or "").casefold()
    relative = str(module.get("relative_path") or "").casefold()
    if not fullname and not relative:
        return module.get("module_type") == "local"
    return not fullname.startswith(NON_WINDOWS_MODULE_PREFIXES) and not relative.startswith(tuple(prefix.replace("exploit/", "exploits/") for prefix in NON_WINDOWS_MODULE_PREFIXES))


def _module_requires_msf(module: dict[str, Any]) -> bool:
    check_method = str(module.get("check_method") or "").casefold()
    if check_method == "local_only":
        return False
    return bool(module.get("fullname") or module.get("module")) or "msf" in check_method


def _normalize_services(services: Iterable[str] | None) -> list[str]:
    normalized = []
    for service in services or []:
        value = str(service or "").strip().casefold()
        if value in SERVICE_COMPONENTS and value not in normalized:
            normalized.append(value)
    return normalized


def _run_safe_msf_check(module: dict[str, Any], target: str, runner: MsfRpcRunner | None = None) -> dict[str, Any]:
    if runner is None:
        manager = get_msf_manager()
        runner = MsfRpcRunner(
            host=manager.config.host,
            port=manager.config.port,
            password=manager.config.password,
            ssl=manager.config.ssl,
        )
    module_path = str(module.get("fullname") or "")
    datastore = _module_default_datastore(module, target)
    try:
        if module.get("module_type") == "auxiliary":
            raw_output = runner.run_module(module_path, datastore)
            command = "run"
        else:
            raw_output = runner.run_check(module_path, datastore)
            command = "check"
    except Exception as exc:
        raw_output = f"MSF check failed: {exc}"
        status = "ERROR"
        command = "check" if module.get("module_type") == "exploit" else "run"
    else:
        status = _msf_check_status(raw_output)
    return {
        "port": datastore.get("RPORT", "module option"),
        "ssl": bool(datastore.get("SSL", False)),
        "datastore": datastore,
        "check_command": command,
        "check_executed": True,
        "status": status,
        "evidence": _msf_check_evidence(raw_output, status),
        "raw_output": raw_output,
    }


def _run_safe_msf_check_timed(
    module: dict[str, Any],
    target: str,
    runner: MsfRpcRunner | None = None,
) -> dict[str, Any]:
    """Run MSF check with a hard timeout so one slow module cannot block the entire scan."""
    module_path = str(module.get("fullname") or "")
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="msf_chk")
    try:
        future = executor.submit(_run_safe_msf_check, module, target, runner)
        return future.result(timeout=_MSF_CHECK_TIMEOUT)
    except concurrent.futures.TimeoutError:
        logger.warning("MSF check hard-timeout (%.0fs) for %s", _MSF_CHECK_TIMEOUT, module_path)
        datastore = _module_default_datastore(module, target)
        return {
            "port": datastore.get("RPORT", "module option"),
            "ssl": bool(datastore.get("SSL", False)),
            "datastore": datastore,
            "check_command": "check",
            "check_executed": False,
            "status": "CHECK_UNSUPPORTED",
            "evidence": f"MSF check timed out after {_MSF_CHECK_TIMEOUT:.0f}s for {module_path}. Module may not respond to check.",
            "raw_output": "",
        }
    except Exception as exc:
        logger.warning("MSF check error for %s: %s", module_path, exc)
        datastore = _module_default_datastore(module, target)
        return {
            "port": datastore.get("RPORT", "module option"),
            "ssl": bool(datastore.get("SSL", False)),
            "datastore": datastore,
            "check_command": "check",
            "check_executed": False,
            "status": "ERROR",
            "evidence": f"MSF check failed: {exc}",
            "raw_output": "",
        }
    finally:
        executor.shutdown(wait=False)


def _local_service_status(local_result: dict[str, Any]) -> str:
    status = str(local_result.get("status") or "INFO").upper()
    if status in {"PASS", "FAIL", "WARNING", "ERROR", "SKIPPED"}:
        return status
    if local_result.get("patch_found") is True:
        return "PASS"
    if local_result.get("patch_found") is False and local_result.get("applicable") is not False:
        return "FAIL"
    return "INFO"


def _module_default_datastore(module: dict[str, Any], target: str) -> dict[str, Any]:
    datastore = dict(module.get("default_datastore") or {})
    datastore["RHOSTS"] = target
    datastore["RHOST"] = target
    datastore["LHOST"] = target
    rport = _int_or_none(module.get("rport"))
    if rport is not None:
        datastore.setdefault("RPORT", rport)
    services = {str(service).casefold() for service in module.get("autofilter_services", [])}
    if "https" in services or datastore.get("RPORT") in {443, 5986, 8531, 8172}:
        datastore.setdefault("SSL", True)
    elif "http" in services or datastore.get("RPORT") in {80, 5985, 8530}:
        datastore.setdefault("SSL", False)
    for component in module.get("components", []):
        defaults = SERVICE_DEFAULT_DATASTORE.get(str(component))
        if defaults:
            for key, value in defaults.items():
                datastore.setdefault(key, value)
            break
    return dict(sorted(datastore.items()))


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _msf_check_status(raw_output: str) -> str:
    output = (raw_output or "").casefold()
    if not output:
        return "INFO"
    if "check method" in output and ("not implemented" in output or "unsupported" in output):
        return "INFO"
    if "does not support check" in output or "check is not supported" in output:
        return "INFO"
    if "appears to be vulnerable" in output or "is vulnerable" in output or "target is vulnerable" in output:
        return "FAIL"
    if "does not appear to be vulnerable" in output or "not vulnerable" in output or "safe" in output:
        return "PASS"
    if "failed" in output or "error" in output or "unknown command" in output:
        return "ERROR"
    return "INFO"


def _msf_confidence(status: str) -> str:
    if status in {"PASS", "FAIL"}:
        return "MSF_CHECK_CONFIRMED"
    if status == "ERROR":
        return "MSF_CHECK_ERROR"
    return "MSF_CHECK_INCONCLUSIVE"


def _msf_check_evidence(raw_output: str, status: str) -> str:
    text = " ".join((raw_output or "").split())
    if text:
        return text[:360]
    if status == "INFO":
        return "MSF safe check completed without a direct vulnerable or patched signal."
    return "MSF safe check completed."


def _normalize_reconfigure_payload(payload: dict[str, Any], *, apply: bool) -> dict[str, Any]:
    if not apply:
        return {"ok": True, "status": "PREVIEW", "requiresReview": True, **payload}
    if payload.get("ok"):
        status = "APPLIED"
    elif payload.get("autoRolledBack"):
        status = "ROLLED_BACK"
    else:
        status = "FAILED"
    return {"status": status, "pendingReboot": False, **payload}


def _error(code: str, message: str) -> dict[str, Any]:
    return {"code": code, "message": message, "severity": "ERROR", "recoverable": True, "details": {}}
