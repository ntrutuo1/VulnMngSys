from __future__ import annotations

from .base import build_ssh_module, windows_ssh_paths
from ..common import rules_file


def module() -> object:
    return build_ssh_module(
        module_id="windows-11-ssh",
        os_family="windows",
        os_version="windows-11",
        display_name="Windows 11 - OpenSSH Server",
        rules_source_file=rules_file("SSH_Ubuntu_24.04.txt"),
        config_paths={"ssh": windows_ssh_paths()},
        prefix="WINSSH",
    )
