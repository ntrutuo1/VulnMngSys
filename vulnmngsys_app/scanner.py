from __future__ import annotations

from pathlib import Path

from .application.factories import get_scanner as _get_scanner
from .application.factories import set_scanner as _set_scanner
from .domain.models import ModuleDefinition, ScanReport
from .infrastructure.scan.components import ComplianceScanner

def get_scanner() -> ComplianceScanner:
    return _get_scanner()


def set_scanner(scanner: ComplianceScanner) -> None:
    _set_scanner(scanner)


def _build_xampp_paths(xampp_root: str, service_type: str) -> dict[str, list[str]]:
    """Build config paths for XAMPP-based services."""
    xampp_path = Path(xampp_root)
    
    if service_type == "apache-http":
        return {
            "apache": [
                str(xampp_path / "apache" / "conf" / "httpd.conf"),
                str(xampp_path / "Apache24" / "conf" / "httpd.conf"),
            ]
        }
    elif service_type == "apache-tomcat":
        return {
            "server": [str(xampp_path / "tomcat" / "conf" / "server.xml")],
            "web": [str(xampp_path / "tomcat" / "conf" / "web.xml")],
            "context": [str(xampp_path / "tomcat" / "conf" / "context.xml")],
        }
    
    return {}


def scan_module(
    module: ModuleDefinition,
    os_version: str | None = None,
    service_version: str | None = None,
    xampp_version: str | None = None,
    xampp_root: str | None = None,
) -> ScanReport:
    # If XAMPP root provided and module is Apache-based, override config paths
    if xampp_root and module.service_type in ("apache-http", "apache-tomcat"):
        xampp_paths = _build_xampp_paths(xampp_root, module.service_type)
        if xampp_paths:
            # Create a new module with XAMPP paths
            module = ModuleDefinition(
                module_id=module.module_id,
                os_family=module.os_family,
                os_version=module.os_version,
                service_type=module.service_type,
                display_name=module.display_name,
                rules_source_file=module.rules_source_file,
                config_paths=xampp_paths,
                checks=module.checks,
                check_metadata=module.check_metadata,
            )
    
    return get_scanner().scan(
        module,
        os_version=os_version,
        service_version=service_version,
        xampp_version=xampp_version,
    )
