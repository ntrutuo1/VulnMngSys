from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
from typing import Any

from .hashing import fnv1a_64, normalize_rule_key


@dataclass(slots=True, frozen=True)
class _RuleIndexItem:
    normalized_key: str
    raw: dict[str, Any]


@dataclass(slots=True, frozen=True)
class _Bucket:
    keys: tuple[str, ...]
    items: tuple[_RuleIndexItem, ...]


class RuleLookupIndex:
    def __init__(self, fast_map: dict[str, dict[str, Any]], buckets: dict[int, _Bucket]) -> None:
        self._fast_map = fast_map
        self._buckets = buckets

    @classmethod
    def from_rules(cls, rules: list[dict[str, Any]]) -> "RuleLookupIndex":
        fast_map: dict[str, dict[str, Any]] = {}
        raw_buckets: dict[int, list[_RuleIndexItem]] = {}

        for rule in rules:
            if not isinstance(rule, dict):
                continue

            candidate_keys = [
                str(rule.get("id") or "").strip(),
                str(rule.get("code") or "").strip(),
            ]

            for key in candidate_keys:
                if not key:
                    continue

                normalized = normalize_rule_key(key)
                fast_map[normalized] = rule
                digest = fnv1a_64(normalized)
                if digest not in raw_buckets:
                    raw_buckets[digest] = []

                raw_buckets[digest].append(_RuleIndexItem(normalized_key=normalized, raw=rule))

        buckets: dict[int, _Bucket] = {}
        for digest, items in raw_buckets.items():
            sorted_items = tuple(sorted(items, key=lambda item: item.normalized_key))
            buckets[digest] = _Bucket(
                keys=tuple(item.normalized_key for item in sorted_items),
                items=sorted_items,
            )

        return cls(fast_map=fast_map, buckets=buckets)

    def get(self, key: str) -> dict[str, Any]:
        normalized = normalize_rule_key(key)
        if not normalized:
            return {}

        fast_hit = self._fast_map.get(normalized)
        if fast_hit is not None:
            return fast_hit

        digest = fnv1a_64(normalized)
        bucket = self._buckets.get(digest)
        if bucket is None:
            return {}

        idx = bisect_left(bucket.keys, normalized)
        if idx < len(bucket.items) and bucket.items[idx].normalized_key == normalized:
            return bucket.items[idx].raw

        return {}
