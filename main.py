from vulnmngsys_app.privilege import ensure_privileged
from vulnmngsys_app.ui import run_app


def main() -> None:
    ensure_privileged()
    run_app()


if __name__ == "__main__":
    main()
