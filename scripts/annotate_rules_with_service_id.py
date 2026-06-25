#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vulnmngsys_app.services.scanflow.json_rule_engine import _load_service_catalog, _classify_rule_service, _normalize_text


def annotate_rules(profile_key: str, rules_dir: Path) -> list[Path]:
    service_catalog = _load_service_catalog(profile_key)
    if not service_catalog:
        print(f"No service catalog for profile: {profile_key}")
        return []

    modified: list[Path] = []
    for p in sorted(rules_dir.glob('*.json')):
        if p.name.endswith('_manifest.json'):
            continue
        if p.name == 'service_catalog.json':
            continue
        try:
            raw = json.loads(p.read_text(encoding='utf-8-sig'))
        except Exception as exc:
            print(f"Skipping {p} (not parseable): {exc}")
            continue
        if not isinstance(raw, list):
            # not a rule list file
            continue
        changed = False
        for idx, item in enumerate(raw):
            if not isinstance(item, dict):
                continue
            # skip if already has service_id
            if item.get('service_id'):
                continue
            svc = _classify_rule_service(item, service_catalog)
            if svc:
                # normalize stored value to the original service name casing
                item['service_id'] = svc
                changed = True
        if changed:
            bak = p.with_suffix(p.suffix + '.bak')
            if not bak.exists():
                bak.write_text(p.read_text(encoding='utf-8-sig'), encoding='utf-8')
            p.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding='utf-8')
            modified.append(p)
            print(f"Annotated {p} with service_id")
    return modified


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--profile', '-p', default='Windows_Server_2022')
    ap.add_argument('--rules-dir', '-r', default=None)
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    rules_dir = Path(args.rules_dir) if args.rules_dir else repo_root / 'rules'
    if not rules_dir.exists():
        raise SystemExit(f"Rules dir not found: {rules_dir}")

    modified = annotate_rules(args.profile, rules_dir)
    print(f"Modified {len(modified)} files")
