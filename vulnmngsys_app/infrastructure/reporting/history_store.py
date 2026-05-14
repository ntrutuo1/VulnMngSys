from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ...domain.models import ScanReport


def _snapshot(report: ScanReport) -> dict:
    return {
        "scan_id": report.scan_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "module_id": report.module.module_id,
        "service_type": report.module.service_type,
        "os_family": report.module.os_family,
        "os_version": report.version_context.get("os_version", report.module.os_version),
        "service_version": report.version_context.get("service_version", ""),
        "hardening_index": report.summary.hardening_index,
        "grade": report.summary.grade,
        "failed_checks": report.summary.failed_checks,
        "warnings": list(report.summary.warnings),
        "vulnerability_findings": [
            {
                "identifier": item.identifier,
                "title": item.title,
                "severity": item.severity,
                "scope": item.scope,
                "confidence": item.confidence,
                "reference": item.reference,
            }
            for item in report.vulnerability_findings
        ],
        "metasploit_results": [
            {
                "module": item.module,
                "target": item.target,
                "success": item.success,
                "summary": item.summary,
            }
            for item in report.metasploit_results
        ],
    }


def append_scan_history(report: ScanReport, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    history_path = output_dir / "scan-history.jsonl"
    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_snapshot(report), ensure_ascii=False))
        handle.write("\n")
    return history_path