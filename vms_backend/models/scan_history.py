from dataclasses import dataclass, field
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanHistory:
    scan_id: str
    target_id: str
    status: str
    scan_type: str
    start_time: str = field(default_factory=utc_now)
    completed_at: str | None = None
    score: int = 0
    summary: dict = field(default_factory=dict)

    def update_status(self, status: str):
        self.status = status
        if status in {"COMPLETED", "FAILED", "CANCELLED"}:
            self.completed_at = utc_now()
