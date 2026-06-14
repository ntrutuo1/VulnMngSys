"""Metasploit RPC runner for safe auxiliary runs and exploit check mode."""
from __future__ import annotations

import time
from typing import Any


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

        try:
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
        timeout: float = 60.0,
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
        timeout: float = 60.0,
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

        mod = client.modules.use(module_type, mod_suffix)
        accepted_datastore: dict[str, Any] = {}
        for key, value in datastore.items():
            try:
                mod[key] = value
                accepted_datastore[key] = value
            except Exception:
                pass

        console = client.consoles.console()
        try:
            self._drain_console(console)
            option_cmds = "\n".join(
                f"set {key} {value}" for key, value in accepted_datastore.items()
            )
            console.write(f"use {module_path}\n{option_cmds}\n{command}\n")

            output_parts: list[str] = []
            elapsed = 0.0
            while elapsed < timeout:
                time.sleep(poll_interval)
                elapsed += poll_interval
                data = console.read()
                chunk = data.get("data", "")
                if chunk:
                    output_parts.append(chunk)
                if not data.get("busy", True):
                    break

            return sanitize_console_output("".join(output_parts))
        finally:
            try:
                console.destroy()
            except Exception:
                pass

    @staticmethod
    def _drain_console(console: Any) -> None:
        for _ in range(3):
            data = console.read()
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
