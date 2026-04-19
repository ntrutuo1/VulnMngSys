from __future__ import annotations

from .base import build_tomcat_module, windows_tomcat_paths
from ..common import rules_file


def module() -> object:
    return build_tomcat_module(
        module_id="windows-generic-tomcat",
        os_family="windows",
        os_version="generic",
        display_name="Windows - Apache Tomcat 10.1",
        rules_source_file=rules_file("Apache_Tomcat.txt"),
        config_paths=windows_tomcat_paths(),
        prefix="WINTOM",
    )
