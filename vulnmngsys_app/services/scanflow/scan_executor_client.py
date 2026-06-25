from __future__ import annotations

from pathlib import Path

from .json_rule_engine import write_merged_scan_from_files
from .paths import project_root


class ScanExecutorError(RuntimeError):
    pass


def _app_root() -> Path:
    return project_root()

def run_scan_via_executor(
    *,
    rule_files: list[Path],
    output_dir: Path,
    profile_key: str = "Windows_Server_2022",
) -> Path:
    """Compatibility wrapper that now delegates to the JSON rule engine."""
    if not rule_files:
        raise ScanExecutorError("No rule files selected for scan")

    output_dir.mkdir(parents=True, exist_ok=True)
    merged_path = write_merged_scan_from_files(
        rule_files,
        output_dir,
        profile_key=profile_key,
    )
    if not merged_path.exists():
        raise ScanExecutorError(f"Merged scan file not found: {merged_path}")

    return merged_path
