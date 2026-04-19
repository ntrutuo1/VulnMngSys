from __future__ import annotations

from .base import build_apache_http_module, windows_apache_paths
from ..common import rules_file


def module() -> object:
    return build_apache_http_module(
        module_id="windows-generic-apache-http",
        os_family="windows",
        os_version="generic",
        display_name="Windows - Apache HTTP Server 2.4",
        rules_source_file=rules_file("Apache_HTTP_server.txt"),
        config_paths={"apache": windows_apache_paths()},
        prefix="WINHTTP",
    )
