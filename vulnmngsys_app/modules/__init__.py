from __future__ import annotations

from ..contracts import ModuleCatalog
from ..models import ModuleDefinition
from .apache import windows_http as apache_windows_http_module
from .apache import windows_tomcat as apache_windows_tomcat_module
from .apache import windows_11_apache_http as apache_windows_http_config_module
from . import windows_server as windows_server_module
from .ssh import windows_11 as ssh_windows_11_module


class HardcodedModuleCatalog(ModuleCatalog):
	def list_modules(self) -> list[ModuleDefinition]:
		return [
			ssh_windows_11_module(),
			apache_windows_http_module(),
			apache_windows_http_config_module(),
			apache_windows_tomcat_module(),
			windows_server_module.build_windows_server_module(),
		]


def load_modules() -> list[ModuleDefinition]:
	return HardcodedModuleCatalog().list_modules()
