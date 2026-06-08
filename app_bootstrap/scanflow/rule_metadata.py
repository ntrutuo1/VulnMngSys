from __future__ import annotations

import re
from typing import Any


def short_reason(value: Any, limit: int = 220) -> str:
    text = " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())
    if not text:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    summary = sentences[0] if sentences else text
    if len(summary) > limit:
        summary = summary[: limit - 1].rsplit(" ", 1)[0].rstrip(",.;:") + "."
    return summary


def cis_reference(profile_key: str, rule_id: Any) -> str:
    rule_text = str(rule_id or "").strip()
    profile_text = str(profile_key or "Windows Server 2022").replace("_", " ")
    if rule_text:
        return f"CIS Microsoft {profile_text} Benchmark, control {rule_text}"
    return f"CIS Microsoft {profile_text} Benchmark"
