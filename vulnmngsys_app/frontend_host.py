from __future__ import annotations

import http.server
import socketserver
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
import sys


class FrontendNotFoundError(FileNotFoundError):
    pass


def resolve_frontend_dir() -> Path:
    candidates: list[Path] = []

    if getattr(sys, "frozen", False):
        base_dir = Path(sys._MEIPASS)
        candidates.extend(
            [
                base_dir / "react-ui" / "dist",
                base_dir / "dist",
            ]
        )
    else:
        project_root = Path(__file__).resolve().parents[1]
        candidates.extend(
            [
                project_root / "react-ui" / "dist",
                project_root / "dist",
            ]
        )

    for candidate in candidates:
        index_file = candidate / "index.html"
        if index_file.exists():
            return candidate

    raise FrontendNotFoundError("React frontend build not found. Run npm run build in react-ui first.")


@contextmanager
def _serve_directory(directory: Path, port: int = 0):
    handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(*args, directory=str(directory), **kwargs)
    with socketserver.ThreadingTCPServer(("127.0.0.1", port), handler) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=1)


def launch_react_frontend(open_browser: bool = True) -> None:
    frontend_dir = resolve_frontend_dir()
    with _serve_directory(frontend_dir) as port:
        url = f"http://127.0.0.1:{port}/"
        if open_browser:
            _launch_firefox_view(url)
            return

        try:
            import webview
        except ModuleNotFoundError:
            raise

        window = webview.create_window(
            title="VulnMngSys Desktop Scanner",
            url=url,
            width=1440,
            height=960,
            min_size=(1100, 760),
            background_color="#0b1020",
            resizable=True,
        )
        webview.start(debug=False)


def _launch_firefox_view(url: str) -> None:
    # Prefer Firefox app-like window mode on Linux.
    commands = [
        ["firefox", "--new-window", "--kiosk", url],
        ["firefox", "--new-window", url],
    ]

    for command in commands:
        try:
            proc = subprocess.Popen(command)
        except OSError:
            continue

        try:
            proc.wait()
        finally:
            # Give the HTTP server a short grace period before teardown.
            time.sleep(0.2)
        return

    raise RuntimeError("Firefox is not available. Install firefox or use --legacy-ui.")
