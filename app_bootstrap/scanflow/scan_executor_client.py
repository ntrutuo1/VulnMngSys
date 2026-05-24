from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path


class ScanExecutorError(RuntimeError):
    pass


def _app_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _executor_script() -> Path:
    return _app_root() / "scripts" / "scan_executor.ps1"


def _run_executor_direct(*, script: Path, rule_list_file: Path, output_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-RuleListFile",
            str(rule_list_file.resolve()),
            "-OutputDir",
            str(output_dir.resolve()),
            "-Quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _parse_payload(stdout: str) -> dict | None:
    text = (stdout or "").strip()
    if not text:
        return None

    candidates = [text]
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines:
        candidates.append(lines[-1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    return None


def run_scan_via_executor(*, rule_files: list[Path], output_dir: Path) -> Path:
    """Luồng quét chính — chỉ entry point scripts/scan_executor.ps1; trả file merged scan."""
    if not rule_files:
        raise ScanExecutorError("No rule files selected for scan")

    script = _executor_script()
    if not script.exists():
        raise ScanExecutorError(f"Missing scan executor: {script}")

    output_dir.mkdir(parents=True, exist_ok=True)
    rule_list_file = output_dir / f"scan_rules_{uuid.uuid4().hex}.lst"
    rule_list_file.write_text(
        "\n".join(str(rule_file.resolve()) for rule_file in rule_files),
        encoding="utf-8",
    )

    try:
        completed = _run_executor_direct(script=script, rule_list_file=rule_list_file, output_dir=output_dir)
    finally:
        rule_list_file.unlink(missing_ok=True)

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()

    payload = _parse_payload(stdout)

    if completed.returncode != 0:
        detail = ""
        if isinstance(payload, dict):
            detail = str(payload.get("error") or "").strip()
        if not detail:
            detail = stderr or stdout or "Unknown scan executor error"
        raise ScanExecutorError(detail)

    if isinstance(payload, dict) and payload.get("ok") is False:
        raise ScanExecutorError(str(payload.get("error") or stderr or stdout or "Scan executor reported failure"))

    merged_scan_file = ""
    if isinstance(payload, dict):
        merged_scan_file = str(payload.get("mergedScanFile") or payload.get("merged_scan_file") or "").strip()

    if not merged_scan_file:
        # Fallback to known merged file path when script output is noisy/non-JSON.
        merged_scan_file = str((output_dir / "scan_results_merged.json").resolve())

    merged_path = Path(merged_scan_file)
    if not merged_path.exists():
        raise ScanExecutorError(f"Merged scan file not found: {merged_path}")

    return merged_path
