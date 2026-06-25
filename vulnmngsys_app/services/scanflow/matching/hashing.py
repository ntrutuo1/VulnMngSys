from __future__ import annotations


def normalize_rule_key(value: str) -> str:
    return value.strip().lower()


def fnv1a_64(text: str) -> int:
    h = 14695981039346656037
    prime = 1099511628211
    for byte_value in text.encode("utf-8", errors="ignore"):
        h ^= byte_value
        h = (h * prime) & 0xFFFFFFFFFFFFFFFF
    return h
