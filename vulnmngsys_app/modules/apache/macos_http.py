from __future__ import annotations

from .base import build_apache_http_module, macos_apache_paths
from ..common import rules_file


def module() -> object:
    return build_apache_http_module(
        module_id="macos-generic-apache-http",
        os_family="macos",
        os_version="generic",
        display_name="macOS - Apache HTTP Server",
        rules_source_file=rules_file("Apache_HTTP_server.txt"),
        config_paths={"apache": macos_apache_paths()},
        prefix="MACHTTP",
    )
