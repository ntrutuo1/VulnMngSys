from dataclasses import dataclass


@dataclass
class CveFinding:
    id: str
    scan_id: str
    evidence: str
    severity: str
    cve_id: str = ""
    affected_service: str = ""
    msf_module: str = ""
    risk_score: float = 0
    patch_status: str = ""

    @property
    def title(self):
        return self.cve_id or self.affected_service or "Service vulnerability finding"
