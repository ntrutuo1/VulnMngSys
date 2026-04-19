from __future__ import annotations

from .http_config_scanner import (
    build_apache_http_config_module,
    linux_apache_http_config_paths,
)
from ..common import rules_file


def ubuntu_22_04_apache_http() -> object:
    return build_apache_http_config_module(
        module_id="linux-ubuntu22-apache-http-config",
        os_family="linux",
        os_version="ubuntu-22.04",
        display_name="HTTP-APACHE-config-scanner (Ubuntu 22.04)",
        rules_source_file=rules_file("Apache_HTTP_server.txt"),
        config_paths={"apache": linux_apache_http_config_paths()},
        prefix="APACHE-HTTP-CFG",
    )
