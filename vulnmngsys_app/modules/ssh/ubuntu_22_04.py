from __future__ import annotations

from .base import build_ssh_module, linux_ssh_paths
from ..common import rules_file


def module() -> object:
    return build_ssh_module(
        module_id="linux-ubuntu22-ssh",
        os_family="linux",
        os_version="ubuntu-22.04",
        display_name="Ubuntu 22.04 - SSH Server",
        rules_source_file=rules_file("SSH_Ubuntu_22.04.txt"),
        config_paths={"ssh": linux_ssh_paths()},
        prefix="U22SSH",
    )
