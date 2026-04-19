from __future__ import annotations

from ...domain.contracts import ModuleCatalog
from ...domain.models import ModuleDefinition
from ...modules.apache import macos_http as apache_macos_http_module
from ...modules.apache import macos_tomcat as apache_macos_tomcat_module
from ...modules.apache import http as apache_linux_http_module
from ...modules.apache import tomcat as apache_linux_tomcat_module
from ...modules.apache import windows_http as apache_windows_http_module
from ...modules.apache import windows_tomcat as apache_windows_tomcat_module
from ...modules.ssh import macos_14 as ssh_macos_14_module
from ...modules.ssh import ubuntu_22_04 as ssh_ubuntu_22_04_module
from ...modules.ssh import ubuntu_24_04 as ssh_ubuntu_24_04_module
from ...modules.ssh import windows_11 as ssh_windows_11_module


class HardcodedModuleCatalog(ModuleCatalog):
    def list_modules(self) -> list[ModuleDefinition]:
        return [
            ssh_ubuntu_22_04_module(),
            ssh_ubuntu_24_04_module(),
            apache_linux_http_module(),
            apache_linux_tomcat_module(),
            apache_windows_http_module(),
            apache_windows_tomcat_module(),
            apache_macos_http_module(),
            apache_macos_tomcat_module(),
            ssh_windows_11_module(),
            ssh_macos_14_module(),
        ]


def load_modules() -> list[ModuleDefinition]:
    return HardcodedModuleCatalog().list_modules()
