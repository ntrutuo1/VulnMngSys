from __future__ import annotations

from .base import build_tomcat_module, macos_tomcat_paths
from ..common import rules_file


def module() -> object:
    return build_tomcat_module(
        module_id="macos-generic-tomcat",
        os_family="macos",
        os_version="generic",
        display_name="macOS - Apache Tomcat",
        rules_source_file=rules_file("Apache_Tomcat.txt"),
        config_paths=macos_tomcat_paths(),
        prefix="MACTOM",
    )
