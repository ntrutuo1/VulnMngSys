from __future__ import annotations

from typing import Any, Protocol


class RuleRepository(Protocol):
    def load_rules(self, profile_key: str, full_scan: bool) -> list[dict[str, Any]]:
        pass
