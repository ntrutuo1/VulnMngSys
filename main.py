import sys
import traceback


def main() -> None:
    try:
        from vulnmngsys_app.startup import (
            parse_cli_args,
            run_legacy_privilege_guard,
        )
    except Exception:
        traceback.print_exc()
        raise SystemExit(2)

    try:
        from vulnmngsys_app.startup.cli import run_cli_scan  # type: ignore
    except Exception:
        def run_cli_scan(**_: object) -> int:
            print(
                "CLI scanner backend is unavailable: missing package 'vulnmngsys_app'.",
                file=sys.stderr,
            )
            return 2

    try:
        from vulnmngsys_app.startup.privilege import ensure_privileged  # type: ignore
    except Exception:
        ensure_privileged = None

    args, unknown_args = parse_cli_args()
    if unknown_args:
        print(f"Ignoring extra arguments: {' '.join(unknown_args)}", file=sys.stderr)

    run_legacy_privilege_guard(ensure_privileged)

    interactive_cli = args.interactive and sys.stdin.isatty()

    if args.cli:
        raise SystemExit(
            run_cli_scan(
                module_id=args.module_id,
                service=args.service,
                os_version=args.os_version,
                service_version=args.service_version,
                interactive=interactive_cli,
            )
        )

    try:
        from vulnmngsys_app.startup.ui import run_desktop_app  # type: ignore
    except Exception as exc:
        print(f"GUI backend unavailable: {exc}", file=sys.stderr)
        raise SystemExit(2)

    raise SystemExit(run_desktop_app())


if __name__ == "__main__":
    main()
