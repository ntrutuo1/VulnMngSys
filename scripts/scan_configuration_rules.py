from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app_bootstrap.scanflow.json_rule_engine import scan_profile, write_merged_scan


def _build_payload(profile_key: str, full_scan: bool) -> dict[str, object]:
    results, rule_files = scan_profile(profile_key, full_scan)
    total = len(results)
    passed = sum(1 for item in results if item.verdict == "PASS")
    failed = sum(1 for item in results if item.verdict == "FAIL")
    manual = sum(1 for item in results if item.verdict == "MANUAL")
    return {
        "profileKey": profile_key,
        "fullScan": full_scan,
        "ruleFiles": [str(path) for path in rule_files],
        "total": total,
        "passed": passed,
        "failed": failed,
        "manual": manual,
        "items": [asdict(item) for item in results],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan Windows configuration rules from the JSON rule catalog")
    parser.add_argument("--profile-key", default="Windows_Server_2022", help="Profile key to scan")
    parser.add_argument("--full", action="store_true", help="Scan the full manifest instead of the quick set")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--write-merged", action="store_true", help="Write the merged scan artifact under reports/temp")
    args = parser.parse_args()

    if args.write_merged:
        merged_path = write_merged_scan(
            args.profile_key,
            args.full,
            PROJECT_ROOT / "reports" / "temp",
        )
        print(str(merged_path))
        return 0

    payload = _build_payload(args.profile_key, args.full)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"Profile: {payload['profileKey']}")
        print(f"Mode   : {'full' if args.full else 'quick'}")
        print(f"Rules  : {payload['total']}")
        print(f"PASS   : {payload['passed']}")
        print(f"FAIL   : {payload['failed']}")
        print(f"MANUAL : {payload['manual']}")

    return 0 if payload["failed"] == 0 and payload["manual"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
