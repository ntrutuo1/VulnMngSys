from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_LOGGER_NAME = "vulnmngsys.remediation"


def remediation_logger(app_root: Path) -> logging.Logger:
    log_dir = app_root / "reports" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "remediation.log"

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler_key = str(log_file.resolve())
    for handler in logger.handlers:
        if getattr(handler, "_vulnmngsys_path", "") == handler_key:
            return logger

    handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    handler._vulnmngsys_path = handler_key
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger


def log_reconfig_event(app_root: Path, event: str, payload: dict[str, Any]) -> None:
    logger = remediation_logger(app_root)
    safe_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    logger.info("%s %s", event, safe_payload)


def close_remediation_loggers() -> None:
    logger = logging.getLogger(_LOGGER_NAME)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
