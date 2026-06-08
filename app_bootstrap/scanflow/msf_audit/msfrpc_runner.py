"""Metasploit RPC runner — connects via pymetasploit3 and executes auxiliary modules."""
from __future__ import annotations

import time
from typing import Any


class MsfRpcConnectionError(Exception):
    """Raised when msfrpc connection cannot be established."""


class MsfRpcRunner:
    """Wraps pymetasploit3 MsfRpcClient with connection test and module execution."""

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
                f"Cannot connect to msfRPC at {self.host}:{self.port} — {exc}"
            ) from exc
        return self._client

    def test_connection(self) -> tuple[bool, str]:
        """Try to connect and return (success, message)."""
        try:
            client = self._get_client()
            # A simple API call to verify the session is alive
            version_attr = client.core.version
            version = version_attr() if callable(version_attr) else version_attr
            framework_version = (version or {}).get("version", "unknown")
            return True, f"Connected — Metasploit Framework {framework_version}"
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
        """Execute an auxiliary module and return its console output.

        Args:
            module_path: Full auxiliary path, e.g. 'auxiliary/scanner/http/http_version'.
            datastore: Key-value options to set on the module.
            poll_interval: Seconds between job status polls.
            timeout: Maximum seconds to wait for module completion.

        Returns:
            Raw console output string.
        """
        client = self._get_client()

        # Strip leading 'auxiliary/' prefix — pymetasploit3 expects the suffix
        mod_suffix = module_path
        if mod_suffix.startswith("auxiliary/"):
            mod_suffix = mod_suffix[len("auxiliary/"):]

        mod = client.modules.use("auxiliary", mod_suffix)
        for key, value in datastore.items():
            try:
                mod[key] = value
            except Exception:
                pass  # Silently skip unsupported options

        # Run via console so we capture real output
        console = client.consoles.console()
        try:
            # Build option set commands then run
            option_cmds = "\n".join(
                f"set {k} {v}" for k, v in datastore.items()
            )
            console.write(f"use {module_path}\n{option_cmds}\nrun\n")

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

            return "".join(output_parts)
        finally:
            try:
                console.destroy()
            except Exception:
                pass
