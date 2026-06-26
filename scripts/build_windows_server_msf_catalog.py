from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnmngsys_app.services.scanflow.msf_audit.local_warehouse import build_windows_server_warehouse


def main() -> int:
    parser = argparse.ArgumentParser(description="Build local Windows Server CVE Metasploit module warehouse.")
    parser.add_argument("--framework-root", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("metasploit_modules") / "warehouse")
    args = parser.parse_args()
    result = build_windows_server_warehouse(framework_root=args.framework_root, output_dir=args.output_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
