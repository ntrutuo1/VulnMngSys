from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .api_helpers import json_response
from .config_routes import handle_config_get, handle_config_post
from .msf_routes import handle_msf_get, handle_msf_post, start_msf_runtime


def create_api_server(host: str = "127.0.0.1", port: int = 5000) -> tuple[ThreadingHTTPServer, threading.Thread]:
    start_msf_runtime()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_OPTIONS(self) -> None:  # noqa: N802
            json_response(self, 200, {"ok": True})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if handle_config_get(self, parsed.path):
                return
            if handle_msf_get(self, parsed.path, parsed.query):
                return
            json_response(self, 404, {"ok": False, "error": "Not found"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if handle_config_post(self, parsed.path):
                return
            if handle_msf_post(self, parsed.path):
                return
            json_response(self, 404, {"ok": False, "error": "Not found"})

    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, name="vulnmngsys-api", daemon=True)
    return server, thread
