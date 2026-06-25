from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from .models import RuleManifest
from .paths import project_root
from .rule_profile_matcher import (
    best_profile_dir,
    is_backup_path,
    normalize_text,
    path_score,
    requested_profile_key,
    sorted_rule_files,
)


def _rules_root() -> Path:
    return project_root() / "rules"


def _unique_text_items(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    items: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = normalize_text(value)
        key = text.casefold()
        if text and key not in seen:
            seen.add(key)
            items.append(text)
    return tuple(items)


def _candidate_names(filename: str) -> tuple[str, ...]:
    base = normalize_text(filename)
    cleaned = base.replace(" copy", "")
    return tuple(dict.fromkeys(item for item in (base, cleaned) if item))


class RuleCatalogError(RuntimeError):
    pass


class RuleManifestError(RuleCatalogError):
    pass


class RuleCatalogService:
    _instance: ClassVar[RuleCatalogService | None] = None

    def __init__(self) -> None:
        self._manifest_cache: dict[str, RuleManifest] = {}
        self._path_cache: dict[tuple[str, str], Path] = {}

    @classmethod
    def instance(cls) -> RuleCatalogService:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def load_manifest(self, profile_key: str | None) -> RuleManifest:
        resolved_key = requested_profile_key(profile_key)
        cached = self._manifest_cache.get(resolved_key.casefold())
        if cached is not None:
            return cached

        manifest = self._build_folder_manifest(resolved_key) or self._load_manifest_file(resolved_key)
        if manifest is None:
            raise RuleManifestError(f"No usable rule profile found for '{resolved_key}'.")
        self._manifest_cache[resolved_key.casefold()] = manifest
        return manifest

    def resolve_rule_path(self, filename: str, *, profile_key: str | None = None) -> Path:
        name = normalize_text(filename)
        if not name:
            raise RuleCatalogError("Rule filename is empty")
        manifest = self.load_manifest(profile_key)
        cache_key = (manifest.profile.casefold(), name.casefold())
        cached = self._path_cache.get(cache_key)
        if cached is not None:
            return cached

        candidates = self._rule_candidates(name, manifest)
        if not candidates:
            raise RuleCatalogError(f"Rule file does not exist: {name}")
        candidates.sort(key=lambda item: (path_score(item, manifest.profile), str(item)))
        self._path_cache[cache_key] = candidates[0]
        return candidates[0]

    def quick_rule_file(self, profile_key: str | None) -> Path:
        manifest = self.load_manifest(profile_key)
        if not manifest.quick:
            raise RuleManifestError(f"Manifest for {manifest.profile} is missing quick rule.")
        return self.resolve_rule_path(manifest.quick, profile_key=manifest.profile)

    def full_rule_files(self, profile_key: str | None) -> list[Path]:
        manifest = self.load_manifest(profile_key)
        if not manifest.full:
            raise RuleManifestError(f"Manifest for {manifest.profile} is missing full rules.")
        return [self.resolve_rule_path(name, profile_key=manifest.profile) for name in manifest.full]

    def _load_manifest_file(self, profile_key: str) -> RuleManifest | None:
        manifest_file = self._discover_manifest_path(profile_key)
        if manifest_file is None:
            return None
        payload = json.loads(manifest_file.read_text(encoding="utf-8-sig"))
        if not isinstance(payload, dict):
            raise RuleManifestError("Manifest must be a JSON object")
        source_dir = best_profile_dir(_rules_root(), profile_key)
        return RuleManifest(
            profile=normalize_text(payload.get("profile") or profile_key) or profile_key,
            quick=normalize_text(payload.get("quick")),
            full=_unique_text_items(payload.get("full")),
            legacy=_unique_text_items(payload.get("legacy")),
            manifest_path=manifest_file,
            source_dir=source_dir,
        )

    def _discover_manifest_path(self, profile_key: str) -> Path | None:
        if "generic" in profile_key.casefold():
            return None
        rules_dir = _rules_root()
        candidates = [rules_dir / f"{profile_key}_manifest.json"]
        candidates.extend(path for path in rules_dir.rglob("*manifest*.json") if path.is_file())
        valid = [path for path in candidates if path.exists() and not is_backup_path(path)]
        if not valid:
            return None
        valid.sort(key=lambda item: (path_score(item, profile_key), str(item)))
        return valid[0]

    def _build_folder_manifest(self, profile_key: str) -> RuleManifest | None:
        profile_dir = best_profile_dir(_rules_root(), profile_key)
        if profile_dir is None:
            return None
        files = sorted_rule_files(profile_dir)
        if not files:
            return None
        names = tuple(path.relative_to(profile_dir).as_posix() for path in files)
        quick = next((name for name in names if name.casefold().endswith("_1.json")), names[0])
        return RuleManifest(profile=profile_dir.name, quick=quick, full=names, source_dir=profile_dir)

    def _rule_candidates(self, filename: str, manifest: RuleManifest) -> list[Path]:
        candidates: list[Path] = []
        roots = [path for path in (manifest.source_dir, _rules_root()) if path is not None]
        for name in _candidate_names(filename):
            for root in roots:
                direct = root / name
                if direct.is_file() and not is_backup_path(direct):
                    candidates.append(direct)
            candidates.extend(path for path in _rules_root().rglob(name) if path.is_file() and not is_backup_path(path))
        return list(dict.fromkeys(candidates))


def get_rule_catalog() -> RuleCatalogService:
    return RuleCatalogService.instance()


def _manifest_path(profile_key: str) -> Path:
    return _rules_root() / f"{profile_key}_manifest.json"


def _find_rule_path(filename: str) -> Path | None:
    try:
        return get_rule_catalog().resolve_rule_path(filename)
    except RuleCatalogError:
        return None


def _load_manifest(profile_key: str) -> dict:
    manifest = get_rule_catalog().load_manifest(profile_key)
    return {
        "profile": manifest.profile,
        "quick": manifest.quick,
        "full": list(manifest.full),
        "legacy": list(manifest.legacy),
        "manifest_path": str(manifest.manifest_path or ""),
        "source_dir": str(manifest.source_dir or ""),
    }


def get_quick_rule_file(profile_key: str | None) -> Path:
    return get_rule_catalog().quick_rule_file(profile_key)


def get_full_rule_files(profile_key: str | None) -> list[Path]:
    return get_rule_catalog().full_rule_files(profile_key)
