from __future__ import annotations

import os
import platform
from typing import Any

from .scan_backend import load_report_file, run_scan_and_save_report


def _wait_before_exit() -> None:
    if platform.system().lower().startswith("win"):
        os.system("pause")
        return

    try:
        input("Press Enter to close...")
    except EOFError:
        pass


def run_headless_scan(
    module_id: str | None = None,
    service: str | None = None,
    os_version: str | None = None,
    service_version: str | None = None,
    interactive: bool = False,
) -> int:
    _ = (module_id, service, os_version, service_version, interactive)

    report: dict[str, Any] = run_scan_and_save_report(mode="quick")
    persisted_report = load_report_file()

    total = int(report.get("total", 0))
    passed = int(report.get("passed", 0))
    failed = int(report.get("failed", 0))
    manual = int(report.get("manual", 0))
    report_file = str(persisted_report.get("reportFile") or report.get("reportFile") or "")

    print(f"Status: {report.get('status')}")
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {failed}")
    print(f"Manual: {manual}")
    print(f"Report saved: {report_file}")
    _wait_before_exit()
    return 0
