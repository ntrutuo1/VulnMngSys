from __future__ import annotations

from .http_config_scanner import (
    build_apache_http_config_module,
    windows_apache_http_config_paths,
)
from ..common import rules_file


def windows_11_apache_http() -> object:
    return build_apache_http_config_module(
        module_id="windows-11-apache-http-config",
        os_family="windows",
        os_version="windows-11",
        display_name="HTTP-APACHE-config-scanner (Windows 11)",
        rules_source_file=rules_file("Apache_HTTP_server.txt"),
        config_paths={"apache": windows_apache_http_config_paths()},
        prefix="APACHE-HTTP-CFG",
    )
