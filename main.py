import sys
import os
import argparse

from vulnmngsys_app.cli import run_headless_scan
from vulnmngsys_app.frontend_host import FrontendNotFoundError, launch_react_frontend
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
    parser.add_argument("--os-version", default=None, help="OS version context for CVE evaluation")
    parser.add_argument("--service-version", default=None, help="Service version context for CVE evaluation")
    parser.add_argument("--legacy-ui", action="store_true", help="Force the old Tkinter UI")
    parser.add_argument("--interactive", action="store_true", help="Interactive CLI step-by-step selection")
    parser.add_argument("--web-ui", action="store_true", help="Allow opening React UI in browser when native webview is unavailable")
    args, unknown_args = parser.parse_known_args()
    if unknown_args:
        filtered = [item for item in unknown_args if item not in {sys.argv[0], os.path.abspath(sys.argv[0])}]
        if filtered:
            print(f"Ignoring extra arguments: {' '.join(filtered)}", file=sys.stderr)

    try:
        from vulnmngsys_app.ui import run_app
    except ModuleNotFoundError as exc:
        if exc.name in {"tkinter", "_tkinter"}:
            print("Tk runtime is unavailable; switching to headless CLI mode.", file=sys.stderr)
            raise SystemExit(
                run_headless_scan(
                    module_id=args.module_id,
                    service=args.service,
                    os_version=args.os_version,
                    service_version=args.service_version,
                )
            ) from exc
        raise

    try:
        ensure_privileged()
    except RuntimeError as exc:
        print(f"Privilege escalation warning: {exc}", file=sys.stderr)
        print("Continuing without elevation. Some config files may not be readable.", file=sys.stderr)

    is_headless_linux = (not sys.platform.startswith("win")) and (not os.environ.get("DISPLAY"))
    interactive_cli = args.interactive or ((args.cli or is_headless_linux) and sys.stdin.isatty())

    if args.cli or is_headless_linux:
        if is_headless_linux and not args.cli:
            print("No DISPLAY detected; running in headless CLI mode.", file=sys.stderr)
        raise SystemExit(
            run_headless_scan(
                module_id=args.module_id,
                service=args.service,
                os_version=args.os_version,
                service_version=args.service_version,
                interactive=interactive_cli,
            )
        )

    if not args.legacy_ui:
        try:
            use_firefox_view = args.web_ui or (sys.platform.startswith("linux") and getattr(sys, "frozen", False))
            launch_react_frontend(open_browser=use_firefox_view)
            return
        except FrontendNotFoundError:
            print("React frontend build not found; falling back to legacy UI.", file=sys.stderr)
        except Exception as exc:
            print(f"React native UI unavailable ({exc}); falling back to legacy UI.", file=sys.stderr)

    try:
        run_app()
    except Exception as exc:
        # Tk can still fail at runtime (for example invalid display binding).
        message = str(exc).lower()
        if "no display name" in message or "couldn't connect to display" in message:
            print("GUI unavailable; switching to headless CLI mode.", file=sys.stderr)
            raise SystemExit(
                run_headless_scan(
                    module_id=args.module_id,
                    service=args.service,
                    os_version=args.os_version,
                    service_version=args.service_version,
                )
            ) from exc
        raise


if __name__ == "__main__":
    main()
