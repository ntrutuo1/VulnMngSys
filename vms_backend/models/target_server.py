from dataclasses import dataclass


@dataclass
class TargetServer:
    target_id: str
    ip_address: str
    os_version: str = ""
    iis_features: str = ""
    running_services: str = ""
