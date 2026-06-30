from dataclasses import dataclass, field


@dataclass
class WindowsCve:
    cve_id: str
    summary: str
    published: str | None = None
    last_update: str | None = None
    max_cvss_base_score: float | None = None
    epss_score: str | None = None
    cisa_kev_added: str | None = None
    public_exploit_exists: str | None = None
    service_keywords: list[str] = field(default_factory=list)
