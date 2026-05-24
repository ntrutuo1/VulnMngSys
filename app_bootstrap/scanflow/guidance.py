from __future__ import annotations

from typing import Any

from .evaluate import format_expected_display


def build_guidance(rule: dict[str, Any], source: str, expected: str) -> list[str]:
    lines: list[str] = []

    gp_path = str(rule.get("gp_path") or "").strip()
    if gp_path:
        lines.append(f"Mở Group Policy theo đường dẫn: {gp_path}")

    if source:
        lines.append(f"Kiểm tra nguồn cấu hình: {source}")

    display_expected = expected or format_expected_display(
        rule.get("expected"),
        str(rule.get("description") or ""),
    )
    if display_expected and not display_expected.startswith("@"):
        lines.append(f"Thiết lập theo khuyến nghị: {display_expected}")

    note = str(rule.get("note") or "").strip()
    if note:
        lines.append(f"Lưu ý: {note}")

    title = str(rule.get("title") or "").strip()
    if title:
        lines.append(f"Xác nhận lại policy: {title}")

    return lines
