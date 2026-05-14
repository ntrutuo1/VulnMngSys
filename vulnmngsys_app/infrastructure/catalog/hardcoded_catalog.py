from __future__ import annotations

from ...domain.contracts import ModuleCatalog
from ...domain.models import ModuleDefinition
from ...modules.apache import windows_http as apache_windows_http_module
from ...modules.apache import windows_tomcat as apache_windows_tomcat_module
from ...modules import windows_server as windows_server_module
from ...modules.ssh import windows_11 as ssh_windows_11_module


class HardcodedModuleCatalog(ModuleCatalog):
    def list_modules(self) -> list[ModuleDefinition]:
        return [
            apache_windows_http_module(),
            apache_windows_tomcat_module(),
            ssh_windows_11_module(),
            windows_server_module.build_windows_server_module(),
        ]


def load_modules() -> list[ModuleDefinition]:
    return HardcodedModuleCatalog().list_modules()
