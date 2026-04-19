from __future__ import annotations

from .base import build_ssh_module, macos_ssh_paths
from ..common import rules_file


def module() -> object:
    return build_ssh_module(
        module_id="macos-14-ssh",
        os_family="macos",
        os_version="macos-14",
        display_name="macOS 14 - OpenSSH",
        rules_source_file=rules_file("SSH_Ubuntu_24.04.txt"),
        config_paths={"ssh": macos_ssh_paths()},
        prefix="MACSSH",
    )
