from __future__ import annotations

import hashlib
import re
from pathlib import Path

RULE_INTEGRITY_MANIFEST = "integrity.sha256"

_DENIED_POWERSHELL_PATTERNS = [
    r"\bInvoke-Expression\b",
    r"\biex\b",
    r"\bInvoke-WebRequest\b",
    r"\biwr\b",
    r"\bInvoke-RestMethod\b",
    r"\birm\b",
    r"\bStart-Process\b",
    r"\bRemove-Item\b",
    r"\bSet-Item\b",
    r"\bSet-ItemProperty\b",
    r"\bNew-Item\b",
    r"\bNew-ItemProperty\b",
    r"\bSet-Service\b",
    r"\bStart-Service\b",
    r"\bStop-Service\b",
    r"\bRestart-Service\b",
    r"\bAdd-MpPreference\b",
    r"\bSet-MpPreference\b",
    r"\breg(?:\.exe)?\s+(?:add|delete|import|restore|save|load|unload)\b",
    r"\b(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)(?:\.exe)?\b",
    r"\b(?:curl|wget)(?:\.exe)?\b",
    r"\bDownload(?:String|File)\b",
]


class RuleIntegrityError(RuntimeError):
    pass


class UnsafePowerShellCommandError(RuntimeError):
    pass


def validate_powershell_check(command: str) -> None:
    for pattern in _DENIED_POWERSHELL_PATTERNS:
        if re.search(pattern, command, flags=re.IGNORECASE):
            raise UnsafePowerShellCommandError(f"Blocked unsafe PowerShell check: {pattern}")


def verify_rule_file_integrity(rule_files: list[Path]) -> None:
    manifest_path = _find_integrity_manifest(rule_files)
    if manifest_path is None:
        return

    expected = _load_integrity_manifest(manifest_path)
    missing: list[str] = []
    mismatched: list[str] = []

    for relative, expected_hash in expected.items():
        candidate = manifest_path.parent / relative
        if not candidate.exists():
            missing.append(relative)
            continue
        actual_hash = _sha256_file(candidate)
        if actual_hash.casefold() != expected_hash.casefold():
            mismatched.append(relative)

    for rule_file in rule_files:
        relative = rule_file.resolve().relative_to(manifest_path.parent.resolve()).as_posix()
        if relative not in expected:
            missing.append(relative)

    if missing or mismatched:
        details = []
        if missing:
            details.append("missing from manifest: " + ", ".join(missing))
        if mismatched:
            details.append("hash mismatch: " + ", ".join(mismatched))
        raise RuleIntegrityError("; ".join(details))


def _find_integrity_manifest(rule_files: list[Path]) -> Path | None:
    for rule_file in rule_files:
        for parent in (rule_file.resolve().parent, *rule_file.resolve().parents):
            manifest = parent / RULE_INTEGRITY_MANIFEST
            if manifest.exists():
                return manifest
    return None


def _load_integrity_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        digest, relative = parts
        entries[relative.replace("\\", "/")] = digest
    return entries


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
