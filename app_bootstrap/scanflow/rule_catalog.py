from __future__ import annotations

import json
import os
import shutil
from pathlib import Path


class RuleManifestError(RuntimeError):
    pass


def _manifest_path(profile_key: str) -> Path:
    rules_dir = Path(__file__).resolve().parents[2] / "rules"
    return rules_dir / f"{profile_key}_manifest.json"


def _find_rule_path(filename: str) -> Path | None:
    """Search `rules` directory for a filename; prefer root over plain_backup."""
    rules_dir = Path(__file__).resolve().parents[2] / "rules"
    candidate = rules_dir / filename
    if candidate.exists():
        return candidate

    for p in rules_dir.rglob(filename):
        if not p.is_file():
            continue
        if "plain_backup" in p.parts:
            continue
        return p

    for p in rules_dir.rglob(filename):
        if p.is_file():
            return p
    return None


def _load_manifest(profile_key: str) -> dict:
    manifest_file = _manifest_path(profile_key)
    if not manifest_file.exists():
        # fallback: search recursively for manifest json (handles plain_backup)
        rules_dir = Path(__file__).resolve().parents[2] / "rules"
        # try exact name first
        found = _find_rule_path(f"{profile_key}_manifest.json")
        if not found:
            # look for any json file mentioning profile_key and 'manifest'
            candidates = list(rules_dir.rglob(f"*{profile_key}*manifest*.json"))
            if candidates:
                found = candidates[0]
        if found:
            manifest_file = found
            # if manifest was found in a nested folder (e.g., plain_backup),
            # copy it into the top-level rules dir so other code that expects
            # rules/<manifest> can find it in the packaged temp extraction.
            try:
                rules_dir = Path(__file__).resolve().parents[2] / "rules"
                dest = rules_dir / manifest_file.name
                if manifest_file.parent != rules_dir and not dest.exists():
                    shutil.copy2(manifest_file, dest)
                    manifest_file = dest
            except Exception:
                # if copy fails, continue using the discovered path
                pass
        else:
            # helpful debug: list a few files under rules to aid diagnosis
            sample = []
            try:
                for i, p in enumerate(rules_dir.rglob('*.json')):
                    sample.append(str(p.relative_to(rules_dir)))
                    if i >= 20:
                        break
            except Exception:
                pass
            raise RuleManifestError(f"Không tìm thấy manifest: {manifest_file}. Available samples: {sample}")
    payload = json.loads(manifest_file.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise RuleManifestError("Manifest phải là object JSON")
    return payload


def get_quick_rule_file(profile_key: str) -> Path:
    manifest = _load_manifest(profile_key)
    quick_name = str(manifest.get("quick") or "").strip()
    if not quick_name:
        raise RuleManifestError("Manifest thiếu trường `quick`")

    # resolve file by name; support files in plain_backup
    found = _find_rule_path(quick_name)
    if not found:
        raise RuleManifestError(f"Quick rule file không tồn tại: {quick_name}")
    return found


def get_full_rule_files(profile_key: str) -> list[Path]:
    manifest = _load_manifest(profile_key)
    full_items = manifest.get("full")
    if not isinstance(full_items, list) or not full_items:
        raise RuleManifestError("Manifest thiếu danh sách `full`")

    files: list[Path] = []
    for name in full_items:
        item_name = str(name).strip()
        found = _find_rule_path(item_name)
        if not found:
            raise RuleManifestError(f"Full rule file không tồn tại: {item_name}")
        files.append(found)
    return files
