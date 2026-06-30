from dataclasses import dataclass


@dataclass
class CisFinding:
    id: str
    scan_id: str
    title: str
    evidence: str
    status: str
    remediation: str = ""
    rule_id: str = ""
    is_passed: bool = False
    registry_key: str = ""

    @property
    def severity(self):
        return "low" if self.is_passed else "medium"
