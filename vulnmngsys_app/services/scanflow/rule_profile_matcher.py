from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


def normalize_text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def is_backup_path(path: Path) -> bool:
    parts = [part.casefold() for part in path.parts]
    return any(part == "plain_backup" or part.endswith("_backup") for part in parts)


def profile_tokens(value: str) -> tuple[str, ...]:
    normalized = normalize_text(value).casefold()
    tokens = re.findall(r"[a-z0-9]+", normalized)
    for year in re.findall(r"\d{4}", normalized):
        tokens.extend([year, f"win{year}"])
    return tuple(dict.fromkeys(token for token in tokens if token))


def requested_profile_key(value: str | None) -> str:
    override = normalize_text(os.getenv("VULNMNGSYS_RULE_PROFILE"))
    if override:
        return override
    return normalize_text(value) or "Windows_Server_Generic"


def best_profile_dir(rules_dir: Path, profile_key: str) -> Path | None:
    dirs = [
        path
        for path in rules_dir.iterdir()
        if path.is_dir() and path.name.casefold() != "common" and not is_backup_path(path)
    ]
    scored = [(_profile_dir_score(path, profile_key), path) for path in dirs if list(path.glob("*.json"))]
    if not scored:
        return None
    scored.sort(key=lambda item: item[0])
    return scored[0][1]


def sorted_rule_files(profile_dir: Path) -> list[Path]:
    files = [
        path
        for path in profile_dir.rglob("*.json")
        if path.is_file() and not is_backup_path(path) and _is_usable_rule_file(path)
    ]
    return sorted(files, key=lambda path: (_rule_file_score(path), path.relative_to(profile_dir).as_posix().casefold()))


def path_score(path: Path, profile_key: str | None) -> tuple[int, int, int, str]:
    if is_backup_path(path):
        return (10_000, len(path.parts), len(path.name), str(path))
    parts = [part.casefold() for part in path.parts]
    normalized_profile = normalize_text(profile_key or "").casefold()
    comparable_profile = re.sub(r"[^a-z0-9]+", "", normalized_profile)
    comparable_path = re.sub(r"[^a-z0-9]+", "", str(path).casefold())
    if comparable_profile and comparable_profile in comparable_path:
        return (-1, len(path.parts), len(path.name), str(path))
    tokens = profile_tokens(normalized_profile)
    rank = len(tokens) + 1
    for index, token in enumerate(tokens):
        if any(token in part for part in parts):
            rank = index
            break
    return (rank, len(path.parts), len(path.name), str(path))


def _profile_dir_score(path: Path, profile_key: str) -> tuple[int, int, int, str]:
    name = path.name.casefold()
    tokens = profile_tokens(profile_key)
    requested_year = _first_year(profile_key)
    folder_year = _first_year(path.name)
    misses = sum(1 for token in tokens if token not in name)
    year_distance = abs(requested_year - folder_year) if requested_year and folder_year else 999
    bonus = 0
    if "stig" in tokens and "stig" in name:
        bonus -= 5
    if "azure" in tokens and "azure" in name:
        bonus -= 5
    if {"standard", "stand", "alone"} & set(tokens) and ("standard" in name or "stand" in name):
        bonus -= 4
    return (year_distance, misses + bonus, len(name), name)


def _rule_file_score(path: Path) -> tuple[int, tuple[int, ...], str]:
    stem = path.stem.casefold()
    numbers = tuple(int(value) for value in re.findall(r"\d+", stem))
    chapter_numbers = numbers[1:] if numbers and numbers[0] >= 2000 else numbers
    return (0 if chapter_numbers == (1,) else 1, chapter_numbers or (999,), stem)


def _first_year(value: str) -> int | None:
    match = re.search(r"(20\d{2})", value)
    return int(match.group(1)) if match else None


def _is_usable_rule_file(path: Path) -> bool:
    try:
        if path.stat().st_size <= 0:
            return False
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False
    return isinstance(payload, list)
