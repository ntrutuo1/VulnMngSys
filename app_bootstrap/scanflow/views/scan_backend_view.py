from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from app_bootstrap.scanflow.inventory import load_windows_inventory
from app_bootstrap.scanflow.rule_catalog import get_rule_catalog
from app_bootstrap.scanflow.scanner import run_scan_for_profile

from .scan_view import get_scan_view


SCAN_FEATURE_MESSAGE = "The new scan flow uses the internal JSON rule engine."


class ScanBackendView:
    _instance: ClassVar[ScanBackendView | None] = None

    def __init__(self) -> None:
        self._view = get_scan_view()

    @classmethod
    def instance(cls) -> ScanBackendView:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_resource_path(self, relative_path: str) -> Path:
        base_path = Path(__file__).resolve().parents[3]
        return base_path / relative_path

    def default_profile_key(self) -> str:
        try:
            inventory = load_windows_inventory()
            if inventory.profile_key:
                return inventory.profile_key
        except Exception:
            pass
        return "Windows_Server_2022"

    def app_root(self) -> Path:
        return Path(__file__).resolve().parents[3]

    def report_file(self) -> Path:
        return self.app_root() / "reports" / "scan_compare_report.json"

    def run_profile_scan(
        self,
        *,
        profile_key: str | None = None,
        full_scan: bool = False,
    ) -> dict[str, Any]:
        requested_profile = profile_key or self.default_profile_key()
        selected_profile = get_rule_catalog().load_manifest(requested_profile).profile
        try:
            inventory = load_windows_inventory()
        except Exception:
            inventory = None

        merged_scan_file = run_scan_for_profile(
            profile_key=selected_profile,
            full_scan=full_scan,
            inventory=inventory,
        )

        raw_payload = json.loads(merged_scan_file.read_text(encoding="utf-8-sig"))
        normalized_rows = [self._view.normalize_row(row) for row in self._view.flatten_rows(raw_payload)]
        report_payload = self._view.build_report_payload(
            profile_key=selected_profile,
            full_scan=full_scan,
            merged_scan_file=merged_scan_file,
            rows=normalized_rows,
        )
        return {
            "ok": True,
            **report_payload,
        }

    def run_scan_and_save_report(
        self,
        *,
        profile_key: str | None = None,
        mode: str = "quick",
    ) -> dict[str, Any]:
        return self.run_profile_scan(
            profile_key=profile_key,
            full_scan=mode == "full",
        )

    def load_report_file(self, report_file: Path | None = None) -> dict[str, Any]:
        path = report_file or self.report_file()
        if not path.exists():
            raise FileNotFoundError(SCAN_FEATURE_MESSAGE)
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(payload, dict):
            payload.setdefault("ok", True)
            return self._view.normalize_report_payload(payload)
        return payload


def get_scan_backend_view() -> ScanBackendView:
    return ScanBackendView.instance()


def get_resource_path(relative_path: str) -> Path:
    return get_scan_backend_view().get_resource_path(relative_path)


def run_profile_scan(
    *,
    profile_key: str | None = None,
    full_scan: bool = False,
) -> dict[str, Any]:
    return get_scan_backend_view().run_profile_scan(
        profile_key=profile_key,
        full_scan=full_scan,
    )


def run_scan_and_save_report(
    *,
    profile_key: str | None = None,
    mode: str = "quick",
) -> dict[str, Any]:
    return get_scan_backend_view().run_scan_and_save_report(
        profile_key=profile_key,
        mode=mode,
    )


def load_report_file(report_file: Path | None = None) -> dict[str, Any]:
    return get_scan_backend_view().load_report_file(report_file)
