from __future__ import annotations

import json
import random
import time
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app_bootstrap.scanflow.matching import RuleLookupIndex, fnv1a_64


def _load_rules(rule_file: Path) -> list[dict]:
    payload = json.loads(rule_file.read_text(encoding="utf-8-sig"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def _build_plain_index(rules: list[dict]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for rule in rules:
        for key in ("id", "code"):
            value = str(rule.get(key) or "").strip().lower()
            if value:
                index[value] = rule
    return index


def main() -> int:
    rule_file = Path("VulnMngSys/rules/Windows_Server_2022_18_2.json").resolve()
    rules = _load_rules(rule_file)
    if not rules:
        print("No rules found for benchmark")
        return 2

    # amplify dataset
    expanded: list[dict] = []
    for block in range(8000):
        for rule in rules:
            clone = dict(rule)
            rid = str(clone.get("id") or clone.get("code") or "")
            clone["id"] = f"{rid}-{block}"
            expanded.append(clone)

    keys = [str(item.get("id") or "").strip().lower() for item in expanded if item.get("id")]
    random.shuffle(keys)

    plain_start = time.perf_counter()
    plain_index = _build_plain_index(expanded)
    plain_build = time.perf_counter() - plain_start

    hash_start = time.perf_counter()
    hashed_index = RuleLookupIndex.from_rules(expanded)
    hash_build = time.perf_counter() - hash_start

    lookup_keys = keys[: min(len(keys), 50000)]

    plain_lookup_start = time.perf_counter()
    plain_hits = sum(1 for key in lookup_keys if plain_index.get(key))
    plain_lookup = time.perf_counter() - plain_lookup_start

    hash_lookup_start = time.perf_counter()
    hash_hits = sum(1 for key in lookup_keys if hashed_index.get(key))
    hash_lookup = time.perf_counter() - hash_lookup_start

    sample = lookup_keys[0]
    print(
        json.dumps(
            {
                "rules": len(expanded),
                "sample_key": sample,
                "sample_hash_fnv1a_64": fnv1a_64(sample),
                "plain_build_sec": round(plain_build, 6),
                "hash_build_sec": round(hash_build, 6),
                "plain_lookup_sec": round(plain_lookup, 6),
                "hash_lookup_sec": round(hash_lookup, 6),
                "plain_hits": plain_hits,
                "hash_hits": hash_hits,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
