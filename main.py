import sys
import os
import argparse

from vulnmngsys_app.cli import run_headless_scan
from vulnmngsys_app.privilege import ensure_privileged


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnMngSys Desktop/CLI Scanner")
    parser.add_argument("--cli", action="store_true", help="Force headless CLI mode")
    parser.add_argument("--module-id", default=None, help="Run a specific hardcoded module id")
    parser.add_argument(
        "--service",
        default="ssh",
        choices=["ssh", "apache-http", "apache-tomcat"],
        help="Service type in CLI mode",
    )
    args = parser.parse_args()

    try:
        from vulnmngsys_app.ui import run_app
    except ModuleNotFoundError as exc:
        if exc.name in {"tkinter", "_tkinter"}:
            print("Tk runtime is unavailable; switching to headless CLI mode.", file=sys.stderr)
            raise SystemExit(run_headless_scan(module_id=args.module_id, service=args.service)) from exc
        raise

    try:
        ensure_privileged()
    except RuntimeError as exc:
        print(f"Privilege escalation warning: {exc}", file=sys.stderr)
        print("Continuing without elevation. Some config files may not be readable.", file=sys.stderr)

    is_headless_linux = (not sys.platform.startswith("win")) and (not os.environ.get("DISPLAY"))
    if args.cli or is_headless_linux:
        if is_headless_linux and not args.cli:
            print("No DISPLAY detected; running in headless CLI mode.", file=sys.stderr)
        raise SystemExit(run_headless_scan(module_id=args.module_id, service=args.service))

    try:
        run_app()
    except Exception as exc:
        # Tk can still fail at runtime (for example invalid display binding).
        message = str(exc).lower()
        if "no display name" in message or "couldn't connect to display" in message:
            print("GUI unavailable; switching to headless CLI mode.", file=sys.stderr)
            raise SystemExit(run_headless_scan(module_id=args.module_id, service=args.service)) from exc
        raise


if __name__ == "__main__":
    main()
