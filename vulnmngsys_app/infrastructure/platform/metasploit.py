from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess


@dataclass(frozen=True, slots=True)
class MetasploitScanResult:
    module: str
    target: str
    success: bool
    summary: str
    output: str = ""


def _msf_available() -> bool:
    return shutil.which("msfconsole") is not None


def _truncate(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _summarize_output(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in lines:
        lowered = line.lower()
        if lowered.startswith("[+") or lowered.startswith("[-") or "detected" in lowered:
            return line
    return lines[0] if lines else ""


def _rules_root() -> Path:
    return Path(__file__).resolve().parents[3] / "rules"


def _load_windows_modules() -> list[dict[str, object]]:
    rules_path = _rules_root() / "metasploit_windows_modules.json"
    if not rules_path.exists():
        return [
            {"module": "auxiliary/scanner/smb/smb_version", "enabled": True, "options": {}},
            {"module": "auxiliary/scanner/rdp/rdp_scanner", "enabled": True, "options": {}},
        ]
    try:
        payload = json.loads(rules_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    modules = payload.get("modules", []) if isinstance(payload, dict) else []
    if not isinstance(modules, list):
        return []
    cleaned: list[dict[str, object]] = []
    for item in modules:
        if not isinstance(item, dict):
            continue
        module = str(item.get("module", "")).strip()
        if not module:
            continue
        enabled = bool(item.get("enabled", True))
        options = item.get("options", {})
        if not isinstance(options, dict):
            options = {}
        cleaned.append({"module": module, "enabled": enabled, "options": options})
    return cleaned


def run_windows_service_scan(target_host: str, timeout_sec: int = 90) -> list[MetasploitScanResult]:
    if not target_host.strip():
        return []
    if not _msf_available():
        return [
            MetasploitScanResult(
                module="msfconsole",
                target=target_host,
                success=False,
                summary="msfconsole not found in PATH",
                output="",
            )
        ]

    results: list[MetasploitScanResult] = []
    modules = _load_windows_modules()
    for entry in modules:
        if not entry.get("enabled", True):
            continue
        module = str(entry.get("module", "")).strip()
        options = entry.get("options", {})
        command_parts = [f"use {module}", f"set RHOSTS {target_host}"]
        if isinstance(options, dict):
            for key, value in options.items():
                key_text = str(key).strip()
                value_text = str(value).strip()
                if not key_text:
                    continue
                command_parts.append(f"set {key_text} {value_text}")
        command_parts.extend(["run", "exit -y"])
        cmd = "; ".join(command_parts)
        try:
            completed = subprocess.run(
                ["msfconsole", "-q", "-x", cmd],
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_sec,
            )
            output = (completed.stdout or "") + "\n" + (completed.stderr or "")
            summary = _summarize_output(output)
            results.append(
                MetasploitScanResult(
                    module=module,
                    target=target_host,
                    success=completed.returncode == 0,
                    summary=summary,
                    output=_truncate(output.strip()),
                )
            )
        except subprocess.TimeoutExpired:
            results.append(
                MetasploitScanResult(
                    module=module,
                    target=target_host,
                    success=False,
                    summary="Scan timed out",
                    output="",
                )
            )
        except OSError as exc:
            results.append(
                MetasploitScanResult(
                    module=module,
                    target=target_host,
                    success=False,
                    summary=f"Execution failed: {exc}",
                    output="",
                )
            )

    return results