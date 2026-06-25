from __future__ import annotations

AUDITPOL_BITMASKS = {
    0: 0,
    1: 1,
    2: 2,
    3: 3,
}

AUDITPOL_TEXT_TO_MASK = {
    "no auditing": 0,
    "success": 1,
    "failure": 2,
    "success and failure": 3,
    "success/failure": 3,
    "success, failure": 3,
    "failure and success": 3,
}
