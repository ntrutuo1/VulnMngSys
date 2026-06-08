from __future__ import annotations

import json
import hmac
from http.server import BaseHTTPRequestHandler
from typing import Any

MAX_JSON_BODY_BYTES = 1024 * 1024


class RequestBodyTooLarge(ValueError):
    pass


class InvalidJsonBody(ValueError):
    pass


def _allowed_origin(handler: BaseHTTPRequestHandler) -> str:
    origin = handler.headers.get("Origin") or ""
    allowed = getattr(handler.server, "allowed_origins", set())
    if origin in allowed:
        return origin
    # If no Origin is provided (e.g. CLI), we don't send CORS headers
    # If it's not in the allowed list, we don't send CORS headers
    return ""


def is_authorized(handler: BaseHTTPRequestHandler) -> bool:
    expected = getattr(handler.server, "api_token", "")
    if not expected:
        return True
    provided = handler.headers.get("X-VulnMngSys-Token") or ""
    return hmac.compare_digest(str(provided), str(expected))


def is_action_allowed(handler: BaseHTTPRequestHandler, action: str) -> bool:
    allowed = getattr(handler.server, "allowed_actions", None)
    if allowed is None:
        return True
    return action in allowed


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    origin = _allowed_origin(handler)
    if origin:
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Vary", "Origin")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, X-VulnMngSys-Token")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    handler.end_headers()
    handler.wfile.write(raw)


def error_response(handler: BaseHTTPRequestHandler, status: int, error_code: str, message: str) -> None:
    json_response(
        handler,
        status,
        {
            "ok": False,
            "errorCode": error_code,
            "error": message,
        },
    )


def server_error_response(
    handler: BaseHTTPRequestHandler,
    error_code: str,
    message: str = "The operation failed. Review logs for details.",
) -> None:
    error_response(handler, 500, error_code, message)


def read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    try:
        length = int(handler.headers.get("Content-Length") or 0)
        if length > MAX_JSON_BODY_BYTES:
            raise RequestBodyTooLarge(f"JSON body exceeds {MAX_JSON_BODY_BYTES} bytes")
        raw_body = handler.rfile.read(length).decode("utf-8") if length else "{}"
        body = json.loads(raw_body or "{}")
        return body if isinstance(body, dict) else {}
    except RequestBodyTooLarge:
        raise
    except json.JSONDecodeError as exc:
        raise InvalidJsonBody("Invalid JSON body") from exc
    except Exception:
        return {}
