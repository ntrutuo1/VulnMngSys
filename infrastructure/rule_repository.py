from __future__ import annotations

from typing import Any

from app_bootstrap.scanflow.json_rule_engine import _load_json_rules, _load_rule_files, _prepare_rules_for_scan
from app_bootstrap.scanflow.security import verify_rule_file_integrity


class JsonRuleRepository:
    """Loads JSON rule profiles through the legacy-compatible rule engine helpers."""

    def load_rules(self, profile_key: str, full_scan: bool) -> list[dict[str, Any]]:
        rule_files = _load_rule_files(profile_key, full_scan)
        verify_rule_file_integrity(rule_files)
        rules: list[dict[str, Any]] = _load_json_rules(rule_files)
        return _prepare_rules_for_scan(rules, profile_key=profile_key)
