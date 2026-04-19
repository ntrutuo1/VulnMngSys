from __future__ import annotations

from ..contracts import ModuleCatalog
from ..models import ModuleDefinition
from .apache import macos_http as apache_macos_http_module
from .apache import macos_tomcat as apache_macos_tomcat_module
from .apache import http as apache_linux_http_module
from .apache import tomcat as apache_linux_tomcat_module
from .apache import windows_http as apache_windows_http_module
from .apache import windows_tomcat as apache_windows_tomcat_module
from .apache import ubuntu_22_04_apache_http as apache_ubuntu_http_config_module
from .apache import windows_11_apache_http as apache_windows_http_config_module
from .ssh import macos_14 as ssh_macos_14_module
from .ssh import ubuntu_22_04 as ssh_ubuntu_22_04_module
from .ssh import ubuntu_24_04 as ssh_ubuntu_24_04_module
from .ssh import windows_11 as ssh_windows_11_module


class HardcodedModuleCatalog(ModuleCatalog):
	def list_modules(self) -> list[ModuleDefinition]:
		return [
			ssh_ubuntu_22_04_module(),
			ssh_ubuntu_24_04_module(),
			ssh_windows_11_module(),
			ssh_macos_14_module(),
			apache_linux_http_module(),
			apache_windows_http_module(),
			apache_macos_http_module(),
			apache_ubuntu_http_config_module(),
			apache_windows_http_config_module(),
			apache_linux_tomcat_module(),
			apache_windows_tomcat_module(),
			apache_macos_tomcat_module(),
		]


def load_modules() -> list[ModuleDefinition]:
	return HardcodedModuleCatalog().list_modules()
