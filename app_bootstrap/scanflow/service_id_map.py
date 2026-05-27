from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

SERVICE_LIST_PATH = Path(__file__).resolve().parents[2] / "rules" / "service_list.json"


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalize_name(value: Any) -> str:
    return _normalize_text(value).casefold()


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = _normalize_text(value)
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


@lru_cache(maxsize=1)
def load_service_id_maps() -> tuple[dict[int, str], dict[str, int]]:
    if not SERVICE_LIST_PATH.exists():
        return {}, {}

    raw = json.loads(SERVICE_LIST_PATH.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, list):
        return {}, {}

    id_to_name: dict[int, str] = {}
    name_to_id: dict[str, int] = {}

    for item in raw:
        if not isinstance(item, dict):
            continue
        service_id = _to_int(item.get("service_id"))
        service_name = _normalize_text(item.get("service"))
        if service_id is None or not service_name:
            continue
        id_to_name[service_id] = service_name
        name_to_id[_normalize_name(service_name)] = service_id

    return id_to_name, name_to_id


def valid_service_ids() -> set[int]:
    id_to_name, _ = load_service_id_maps()
    return set(id_to_name.keys())


def service_name_from_id(service_id: int) -> str:
    id_to_name, _ = load_service_id_maps()
    return id_to_name.get(service_id, "")


def normalize_service_id(value: Any) -> int | None:
    return _to_int(value)


def service_ids_from_names(names: set[str]) -> set[int]:
    _, name_to_id = load_service_id_maps()
    ids: set[int] = set()
    for name in names:
        normalized = _normalize_name(name)
        if not normalized:
            continue
        mapped = name_to_id.get(normalized)
        if mapped is not None:
            ids.add(mapped)
    return ids


def service_names_from_ids(ids: set[int]) -> set[str]:
    id_to_name, _ = load_service_id_maps()
    names: set[str] = set()
    for service_id in ids:
        name = id_to_name.get(service_id)
        if name:
            names.add(name)
    return names
