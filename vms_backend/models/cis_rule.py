from dataclasses import dataclass


@dataclass
class CisRule:
    hash_id: str
    benchmark: str
    source_file: str
    rule_id: str
    title: str
    powershell_check: str
    expected: str
    operator: str = "=="
    service: str = ""
    check_type: str = ""
    registry_path: str = ""
    remediation: str = ""
    reason: str = ""
    service_id: int = 0
    enabled: bool = True
