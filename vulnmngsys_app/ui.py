from __future__ import annotations

import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

import webview

from .frontend.api_server import create_api_server
from app_bootstrap.scanflow.views.scan_backend_view import get_resource_path


def _resolve_frontend_dist() -> Path:
    return get_resource_path("vulnmngsys_app/frontend/dist")


def _start_server(server: ThreadingHTTPServer, name: str) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    thread.start()
    return thread


def _build_frontend_url(api_host: str, api_port: int, ui_host: str, ui_port: int, api_token: str) -> str:
    query = urlencode({"apiBase": f"http://{api_host}:{api_port}", "apiToken": api_token})
    return f"http://{ui_host}:{ui_port}/?{query}"


def run_desktop_app(api_host: str = "127.0.0.1", api_port: int = 5000, ui_host: str = "127.0.0.1", ui_port: int = 5001) -> int:
    dist_dir = _resolve_frontend_dist()
    index_file = dist_dir / "index.html"
    if not index_file.exists():
        print(f"Frontend build not found: {index_file}")
        return 2

    allowed_origins = {f"http://{ui_host}:{ui_port}"}
    api_server, api_thread = create_api_server(host=api_host, port=api_port, allowed_origins=allowed_origins)
    api_thread.start()

    ui_handler = partial(SimpleHTTPRequestHandler, directory=str(dist_dir))
    ui_server = ThreadingHTTPServer((ui_host, ui_port), ui_handler)
    _start_server(ui_server, "vulnmngsys-ui")

    window = webview.create_window(
        "VulnMngSys",
        _build_frontend_url(api_host, api_port, ui_host, ui_port, getattr(api_server, "api_token", "")),
        width=1440,
        height=960,
    )
    _ = window

    try:
        webview.start()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            ui_server.shutdown()
            ui_server.server_close()
        except Exception:
            pass
        try:
            api_server.shutdown()
            api_server.server_close()
        except Exception:
            pass

    return 0
