from __future__ import annotations

from .base import build_apache_http_module, linux_apache_paths
from ..common import rules_file


def module() -> object:
    return build_apache_http_module(
        module_id="linux-generic-apache-http",
        os_family="linux",
        os_version="generic",
        display_name="Linux - Apache HTTP Server 2.4",
        rules_source_file=rules_file("Apache_HTTP_server.txt"),
        config_paths={"apache": linux_apache_paths()},
        prefix="APHTTP",
    )
