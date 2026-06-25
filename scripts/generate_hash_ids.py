from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


DEFAULT_RULE_DIR = Path(__file__).resolve().parents[1] / "rules" / "CIS-WIN2025"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate stable hash_id values for JSON rules.")
    parser.add_argument("--rule-dir", type=Path, default=DEFAULT_RULE_DIR, help="Rule directory to scan recursively.")
    parser.add_argument("--check", action="store_true", help="Validate hash_id values without writing files.")
    args = parser.parse_args()

    rule_dir = args.rule_dir.resolve()
    if not rule_dir.exists():
        parser.error(f"Rule directory does not exist: {rule_dir}")

    changed_files = 0
    rules_seen = 0
    hashes: dict[str, str] = {}
    collisions: list[str] = []
    stale: list[str] = []
    invalid_files: list[str] = []

    for rule_file in sorted(rule_dir.rglob("*.json")):
        try:
            payload = _load_json(rule_file)
        except json.JSONDecodeError as exc:
            invalid_files.append(f"{rule_file.relative_to(rule_dir).as_posix()}: {exc}")
            continue
        rules = _extract_rules(payload)
        if not rules:
            continue

        file_changed = False
        for rule in rules:
            rules_seen += 1
            next_hash = build_hash_id(rule)
            current_hash = str(rule.get("hash_id") or "").strip()
            rule_ref = f"{rule_file.relative_to(rule_dir).as_posix()}#{rule.get('id', rules_seen)}"

            existing_ref = hashes.get(next_hash)
            if existing_ref and existing_ref != rule_ref:
                collisions.append(f"{next_hash}: {existing_ref}, {rule_ref}")
            hashes[next_hash] = rule_ref

            if current_hash != next_hash:
                stale.append(rule_ref)
                if not args.check:
                    rule["hash_id"] = next_hash
                    file_changed = True

        if file_changed:
            rule_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            changed_files += 1

    if collisions:
        print("Hash collisions detected:")
        for collision in collisions:
            print(f"  {collision}")
        return 2

    if args.check and stale:
        print(f"{len(stale)} rule(s) have missing or stale hash_id values.")
        for item in stale[:20]:
            print(f"  {item}")
        if len(stale) > 20:
            print(f"  ... {len(stale) - 20} more")
        return 1

    action = "validated" if args.check else "updated"
    print(f"{action} {rules_seen} rule(s); {changed_files} file(s) changed; {len(hashes)} unique hash_id value(s).")
    if invalid_files:
        print(f"Skipped {len(invalid_files)} invalid JSON file(s):")
        for item in invalid_files:
            print(f"  {item}")
    return 0


def build_hash_id(rule: dict[str, Any]) -> str:
    fingerprint = "|".join(
        [
            _text(rule.get("service")),
            _text(rule.get("id")),
            _text(rule.get("check_type")),
            _text(rule.get("registry_path") or rule.get("powershell_check")),
        ]
    )
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:12]


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _extract_rules(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        candidates = payload.get("rules") or payload.get("items") or []
        if isinstance(candidates, list):
            return [item for item in candidates if isinstance(item, dict)]
    return []


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


if __name__ == "__main__":
    raise SystemExit(main())
