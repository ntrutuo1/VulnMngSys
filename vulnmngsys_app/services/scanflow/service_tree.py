from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from vulnmngsys_app.services.scanflow.rule_catalog import RuleCatalogError, get_rule_catalog
from vulnmngsys_app.services.scanflow.paths import project_root


RULES_ROOT = project_root() / "rules"


def build_service_tree(
    *,
    profile_key: str | None = None,
    rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a service-oriented view of CIS scan results.

    The returned payload is intentionally plain JSON-compatible data so it can
    be stored in report files and consumed directly by the React UI.
    """

    profile, source_dir = _resolve_profile_dir(profile_key)
    groups = _base_groups_from_rules(source_dir) if source_dir else []
    row_items = rows or []

    if row_items:
        groups = _attach_rows(groups, row_items)
    summary = _summarize_groups(groups)

    return {
        "profileKey": profile or profile_key or "",
        "summary": summary,
        "groups": groups,
    }


def group_rows_by_service(
    rows: list[dict[str, Any]],
    *,
    profile_key: str | None = None,
) -> list[dict[str, Any]]:
    return build_service_tree(profile_key=profile_key, rows=rows)["groups"]


def _resolve_profile_dir(profile_key: str | None) -> tuple[str, Path | None]:
    try:
        manifest = get_rule_catalog().load_manifest(profile_key)
        return manifest.profile, manifest.source_dir
    except RuleCatalogError:
        return profile_key or "", None


def _base_groups_from_rules(source_dir: Path) -> list[dict[str, Any]]:
    groups_by_id: dict[str, dict[str, Any]] = {}
    ordered: list[dict[str, Any]] = []

    for rule_file in sorted(
        source_dir.rglob("*.json"),
        key=lambda path: path.relative_to(source_dir).as_posix().casefold(),
    ):
        if not rule_file.is_file() or _is_backup_path(rule_file):
            continue
        rules = _load_rules(rule_file)
        if not rules:
            continue

        relative = rule_file.relative_to(source_dir)
        if len(relative.parts) == 1:
            service_id = rule_file.stem
            group = groups_by_id.get(service_id)
            if group is None:
                group = _new_group(
                    service_id,
                    category="root",
                    source=str(relative.as_posix()),
                    serviceNumericId=_first_service_id(rules),
                )
                groups_by_id[service_id] = group
                ordered.append(group)
            group["_ruleCount"] += len(rules)
            continue

        folder_id = relative.parts[0]
        parent = groups_by_id.get(folder_id)
        if parent is None:
            parent = _new_group(
                folder_id,
                category="folder",
                source=folder_id,
                subgroups=[],
                serviceNumericId=_first_service_id(rules),
            )
            groups_by_id[folder_id] = parent
            ordered.append(parent)

        child_id = rule_file.stem
        child = _new_group(
            child_id,
            category="file",
            parentServiceId=folder_id,
            source=str(relative.as_posix()),
            serviceNumericId=_first_service_id(rules),
        )
        child["_ruleCount"] = len(rules)
        parent["subgroups"].append(child)
        parent["_ruleCount"] += len(rules)

    return [_finalize_group(group) for group in ordered]


def _attach_rows(base_groups: list[dict[str, Any]], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = deepcopy(base_groups)
    root_lookup: dict[str, dict[str, Any]] = {}
    child_lookup: dict[str, dict[str, Any]] = {}
    id_lookup: dict[str, dict[str, Any]] = {}

    for group in groups:
        root_lookup[_key(group.get("serviceId"))] = group
        id_lookup[_key(group.get("serviceId"))] = group
        for child in group.get("subgroups") or []:
            child_lookup[_key(child.get("serviceId"))] = child
            id_lookup[_key(child.get("serviceId"))] = child

    for row in rows:
        target = _find_target_group(row, root_lookup, child_lookup, id_lookup)
        if target is None:
            target = _new_group(_row_service(row) or "Uncategorized", category="dynamic")
            groups.append(target)
            root_lookup[_key(target.get("serviceId"))] = target
            id_lookup[_key(target.get("serviceId"))] = target
        target.setdefault("items", []).append(row)

    return [_finalize_group(group) for group in groups]


def _find_target_group(
    row: dict[str, Any],
    root_lookup: dict[str, dict[str, Any]],
    child_lookup: dict[str, dict[str, Any]],
    id_lookup: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    service = _row_service(row)
    service_key = _key(service)
    service_id = _coerce_text(row.get("service_id") or row.get("serviceId"))

    if service_key in child_lookup:
        return child_lookup[service_key]
    if service_key in root_lookup:
        return root_lookup[service_key]
    if service_key in id_lookup:
        return id_lookup[service_key]

    if service_id:
        for group in root_lookup.values():
            if _coerce_text(group.get("serviceNumericId")) == service_id:
                subgroups = group.get("subgroups") or []
                if len(subgroups) == 1:
                    return subgroups[0]
                if not subgroups:
                    return group
    return None


def _finalize_group(group: dict[str, Any]) -> dict[str, Any]:
    for child in group.get("subgroups") or []:
        _finalize_group(child)

    own_items = group.get("items") or []
    child_items = [item for child in group.get("subgroups") or [] for item in child.get("items", [])]
    summary_items = own_items + child_items

    counts = _count_rows(summary_items)
    if not summary_items and group.get("total", 0) == 0:
        counts["total"] = int(group.get("_ruleCount") or group.get("ruleCount") or 0)

    group.update(counts)
    group["compliance"] = _compliance(counts)
    if not own_items and group.get("subgroups"):
        group.pop("items", None)
    return _public_group(group)


def _summarize_groups(groups: list[dict[str, Any]]) -> dict[str, Any]:
    items = []
    for group in groups:
        items.extend(group.get("items") or [])
        for child in group.get("subgroups") or []:
            items.extend(child.get("items") or [])
    counts = _count_rows(items)
    if not items:
        counts["total"] = sum(int(group.get("total") or 0) for group in groups)
    counts["compliance"] = _compliance(counts)
    return counts


def _count_rows(rows: list[dict[str, Any]]) -> dict[str, int]:
    passed = failed = manual = 0
    for row in rows:
        verdict = _verdict(row)
        if verdict == "PASS":
            passed += 1
        elif verdict == "MANUAL":
            manual += 1
        else:
            failed += 1
    return {
        "total": len(rows),
        "passed": passed,
        "failed": failed,
        "manual": manual,
    }


def _compliance(counts: dict[str, int]) -> int:
    total = int(counts.get("total") or 0)
    if total <= 0:
        return 0
    return round((int(counts.get("passed") or 0) / total) * 100)


def _load_rules(rule_file: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(rule_file.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        candidates = payload.get("rules") or payload.get("items") or []
        if isinstance(candidates, list):
            return [item for item in candidates if isinstance(item, dict)]
    return []


def _first_service_id(rules: list[dict[str, Any]]) -> str:
    for rule in rules:
        service_id = _coerce_text(rule.get("service_id") or rule.get("serviceId"))
        if service_id:
            return service_id
    return ""


def _new_group(service_id: str, *, category: str, **extra: Any) -> dict[str, Any]:
    group = {
        "serviceId": service_id,
        "label": _label(service_id),
        "category": category,
        "ruleCount": 0,
        "total": 0,
        "passed": 0,
        "failed": 0,
        "manual": 0,
        "items": [],
        **extra,
    }
    group["_ruleCount"] = 0
    return group


def _public_group(group: dict[str, Any]) -> dict[str, Any]:
    public = {key: value for key, value in group.items() if not key.startswith("_")}
    if "_ruleCount" in group:
        public["ruleCount"] = int(group.get("_ruleCount") or group.get("ruleCount") or 0)
    return public


def _row_service(row: dict[str, Any]) -> str:
    return _coerce_text(row.get("service") or row.get("serviceName") or row.get("service_name"))


def _verdict(row: dict[str, Any]) -> str:
    raw = row.get("verdict") or ("PASS" if row.get("passed") else "FAIL")
    return _coerce_text(raw).upper() or "FAIL"


def _label(value: Any) -> str:
    text = _coerce_text(value)
    if not text:
        return "Uncategorized"
    return text.replace("_", " ").replace("-", " ")


def _key(value: Any) -> str:
    return _coerce_text(value).replace(" ", "_").casefold()


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _is_backup_path(path: Path) -> bool:
    parts = [part.casefold() for part in path.parts]
    return any(part == "plain_backup" or part.endswith("_backup") for part in parts)
