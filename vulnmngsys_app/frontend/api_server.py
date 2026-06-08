from __future__ import annotations

import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .api_helpers import InvalidJsonBody, RequestBodyTooLarge, is_authorized, json_response
from .config_routes import handle_config_get, handle_config_post
from .msf_routes import handle_msf_get, handle_msf_post, start_msf_runtime


def _default_allowed_origins() -> set[str]:
    return {
        "http://127.0.0.1:5001",
        "http://localhost:5001",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    }


def _default_allowed_actions() -> set[str]:
    return {"scan", "preview_reconfig", "apply_reconfig", "msf_audit"}


def create_api_server(
    host: str = "127.0.0.1",
    port: int = 5000,
    *,
    api_token: str | None = None,
    allowed_origins: set[str] | None = None,
    allowed_actions: set[str] | None = None,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    start_msf_runtime()
    token = api_token or os.environ.get("VULNMNGSYS_API_TOKEN") or secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_OPTIONS(self) -> None:  # noqa: N802
            json_response(self, 200, {"ok": True})

        def do_GET(self) -> None:  # noqa: N802
            if not is_authorized(self):
                json_response(self, 401, {"ok": False, "error": "Unauthorized"})
                return
            parsed = urlparse(self.path)
            if handle_config_get(self, parsed.path):
                return
            if handle_msf_get(self, parsed.path, parsed.query):
                return
            json_response(self, 404, {"ok": False, "error": "Not found"})

        def do_POST(self) -> None:  # noqa: N802
            if not is_authorized(self):
                json_response(self, 401, {"ok": False, "error": "Unauthorized"})
                return
            parsed = urlparse(self.path)
            try:
                if handle_config_post(self, parsed.path):
                    return
                if handle_msf_post(self, parsed.path):
                    return
            except RequestBodyTooLarge as exc:
                json_response(self, 413, {"ok": False, "error": str(exc)})
                return
            except InvalidJsonBody as exc:
                json_response(self, 400, {"ok": False, "error": str(exc)})
                return
            json_response(self, 404, {"ok": False, "error": "Not found"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.api_token = token
    server.allowed_origins = allowed_origins or _default_allowed_origins()
    server.allowed_actions = allowed_actions or _default_allowed_actions()
    thread = threading.Thread(target=server.serve_forever, name="vulnmngsys-api", daemon=True)
    return server, thread
