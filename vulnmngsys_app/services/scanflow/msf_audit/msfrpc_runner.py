"""Metasploit RPC runner for safe auxiliary runs and exploit check mode."""
from __future__ import annotations

import logging
import socket
import time
from typing import Any

logger = logging.getLogger(__name__)


_PROMPT_PREFIXES = ("msf", "meterpreter")
_BANNER_WORDS = ("metasploit", "rapid7", "destroy.no.data")


class MsfRpcConnectionError(Exception):
    """Raised when msfrpc connection cannot be established."""


def _is_console_noise(line: str) -> bool:
    stripped = line.strip()
    lower = stripped.lower()
    if not stripped:
        return True
    if any(word in lower for word in _BANNER_WORDS):
        return True
    if lower.startswith(_PROMPT_PREFIXES) and ">" in stripped:
        return True
    if lower.startswith(("use ", "set ", "run", "check", "back")):
        return True
    if lower.startswith(("[*] starting", "[*] scanned")):
        return True
    if "=>" in stripped and stripped.split("=>", 1)[0].strip().isupper():
        return True
    decorative = sum(1 for char in stripped if char in "+-=|_/\\:;~*'\"[]{}()<>")
    return len(stripped) >= 20 and decorative / len(stripped) > 0.65


def sanitize_console_output(raw: str) -> str:
    """Remove msfconsole startup banner, prompts, and command echo from output."""
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.strip() for line in lines if not _is_console_noise(line)).strip()


class MsfRpcRunner:
    """Wrap pymetasploit3 MsfRpcClient with connection test and execution helpers."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55552,
        password: str = "",
        ssl: bool = True,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.password = password
        self.ssl = ssl
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazy-connect and return the MsfRpcClient instance."""
        if self._client is not None:
            return self._client
        try:
            from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore[import-untyped]
        except ImportError as exc:
            raise MsfRpcConnectionError(
                "pymetasploit3 is not installed. Run: pip install pymetasploit3"
            ) from exc

        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(15)
            self._client = MsfRpcClient(
                self.password,
                server=self.host,
                port=self.port,
                ssl=self.ssl,
            )
        except Exception as exc:
            raise MsfRpcConnectionError(
                f"Cannot connect to msfRPC at {self.host}:{self.port}: {exc}"
            ) from exc
        finally:
            socket.setdefaulttimeout(prev_timeout)
        return self._client

    def test_connection(self) -> tuple[bool, str]:
        """Try to connect and return (success, message)."""
        try:
            client = self._get_client()
            version_attr = client.core.version
            version = version_attr() if callable(version_attr) else version_attr
            framework_version = (version or {}).get("version", "unknown")
            return True, f"Connected - Metasploit Framework {framework_version}"
        except MsfRpcConnectionError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, f"Connection error: {exc}"

    def run_module(
        self,
        module_path: str,
        datastore: dict[str, Any],
        *,
        poll_interval: float = 0.5,
        timeout: float = 20.0,
    ) -> str:
        """Execute an auxiliary module and return its console output."""
        return self._run_console_command(
            module_path=module_path,
            datastore=datastore,
            expected_type="auxiliary",
            command="run",
            poll_interval=poll_interval,
            timeout=timeout,
        )

    def run_exploit_check(
        self,
        module_path: str,
        datastore: dict[str, Any],
        *,
        poll_interval: float = 0.5,
        timeout: float = 20.0,
    ) -> str:
        """Run an exploit module check without executing a payload."""
        return self._run_console_command(
            module_path=module_path,
            datastore=datastore,
            expected_type="exploit",
            command="check",
            poll_interval=poll_interval,
            timeout=timeout,
        )

    def run_check(
        self,
        module_path: str,
        datastore: dict[str, Any],
        *,
        poll_interval: float = 0.5,
        timeout: float = 20.0,
    ) -> str:
        """Run a module check method without executing a payload/session."""
        module_type, _ = _split_module_path(module_path, default_type="exploit")
        return self._run_console_command(
            module_path=module_path,
            datastore=datastore,
            expected_type=module_type,
            command="check",
            poll_interval=poll_interval,
            timeout=timeout,
        )

    def _run_console_command(
        self,
        *,
        module_path: str,
        datastore: dict[str, Any],
        expected_type: str,
        command: str,
        poll_interval: float,
        timeout: float,
    ) -> str:
        client = self._get_client()
        module_type, mod_suffix = _split_module_path(module_path, default_type=expected_type)
        if module_type != expected_type:
            raise ValueError(f"{command} expects {expected_type} module, got {module_type}")

        try:
            mod = client.modules.use(module_type, mod_suffix)
        except Exception as exc:
            raise RuntimeError(f"Cannot load MSF module {module_path}: {exc}") from exc

        option_names = _module_option_names(mod)
        accepted_datastore = {
            key: value
            for key, value in datastore.items()
            if not option_names or key.upper() in option_names
        }

        try:
            console = client.consoles.console()
        except Exception as exc:
            raise RuntimeError(f"Cannot create MSF console for {module_path}: {exc}") from exc

        try:
            self._drain_console(console)
            option_cmds = "\n".join(
                f"set {key} {_console_value(value)}" for key, value in accepted_datastore.items()
            )
            try:
                console.write(f"use {module_path}\n{option_cmds}\n{command}\n")
            except Exception as exc:
                logger.warning("MSF console write failed for %s: %s", module_path, exc)
                return f"[MSF console write error: {exc}]"

            output_parts: list[str] = []
            elapsed = 0.0
            while elapsed < timeout:
                time.sleep(poll_interval)
                elapsed += poll_interval
                try:
                    data = console.read()
                except Exception as exc:
                    logger.warning("MSF console read failed for %s after %.1fs: %s", module_path, elapsed, exc)
                    output_parts.append(f"[MSF console read error: {exc}]")
                    break
                chunk = data.get("data", "")
                if chunk:
                    output_parts.append(chunk)
                if not data.get("busy", True):
                    break

            if elapsed >= timeout:
                logger.warning("MSF console timed out for %s after %.1fs", module_path, timeout)

            return sanitize_console_output("".join(output_parts))
        finally:
            try:
                console.destroy()
            except Exception:
                pass

    @staticmethod
    def _drain_console(console: Any) -> None:
        for _ in range(3):
            try:
                data = console.read()
            except Exception:
                break
            if not data.get("data"):
                break


def _split_module_path(module_path: str, *, default_type: str) -> tuple[str, str]:
    path = (module_path or "").strip("/")
    if "/" not in path:
        return default_type, path
    module_type, suffix = path.split("/", 1)
    if module_type in {"auxiliary", "exploit"}:
        return module_type, suffix
    return default_type, path


def _module_option_names(module: Any) -> set[str]:
    try:
        options = getattr(module, "options", {}) or {}
        if isinstance(options, dict):
            return {str(key).upper() for key in options}
        return {str(item).upper() for item in options}
    except Exception:
        return set()


def _console_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
