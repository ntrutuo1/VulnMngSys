from __future__ import annotations

from .base import build_tomcat_module, linux_tomcat_paths
from ..common import rules_file


def module() -> object:
    return build_tomcat_module(
        module_id="linux-generic-tomcat",
        os_family="linux",
        os_version="generic",
        display_name="Linux - Apache Tomcat 7/8/9/10/10.1",
        rules_source_file=rules_file("Apache_Tomcat.txt"),
        config_paths=linux_tomcat_paths(),
        prefix="APTOM",
    )
