from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from typing import Iterable

from .frontend.api_server import create_api_server
from .frontend.msf_routes import start_msf_runtime


READY_PREFIX = "VULNMNGSYS_BACKEND_READY "


def _csv_set(value: str | None) -> set[str] | None:
    if not value:
        return None
    items = {item.strip() for item in value.split(",") if item.strip()}
    return items or None


def _parse_allowed_origins(values: Iterable[str], env_value: str | None) -> set[str] | None:
    origins: set[str] = set()
    for value in values:
        origins.update(_csv_set(value) or set())
    origins.update(_csv_set(env_value) or set())
    return origins or None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the VulnMngSys HTTP backend service.")
    parser.add_argument("--host", default=os.getenv("VULNMNGSYS_API_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("VULNMNGSYS_API_PORT", "5000")))
    parser.add_argument("--token", default=os.getenv("VULNMNGSYS_API_TOKEN"))
    parser.add_argument(
        "--allowed-origin",
        action="append",
        default=[],
        help="Allowed CORS origin. Can be repeated or comma-separated.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    allowed_origins = _parse_allowed_origins(args.allowed_origin, os.getenv("VULNMNGSYS_ALLOWED_ORIGINS"))

    server, _thread = create_api_server(
        host=args.host,
        port=args.port,
        api_token=args.token,
        allowed_origins=allowed_origins,
        start_msf=False,
    )

    host, port = server.server_address[:2]
    ready = {
        "ok": True,
        "host": host,
        "port": port,
        "apiBase": f"http://{host}:{port}",
        "apiToken": getattr(server, "api_token", ""),
    }
    print(f"{READY_PREFIX}{json.dumps(ready, separators=(',', ':'))}", flush=True)
    start_msf_runtime()

    stopping = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        server.shutdown()

    try:
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
