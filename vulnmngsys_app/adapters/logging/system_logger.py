import logging
import logging.handlers
import os
from pathlib import Path

ROOT_DIR = Path(os.getenv("VULNMNGSYS_ROOT") or Path(__file__).resolve().parents[3])
LOGS_DIR = ROOT_DIR / "logs"


def setup_system_logger() -> logging.Logger:
    """Set up centralized logging for the desktop app."""
    logger = logging.getLogger("vulnmngsys")

    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            LOGS_DIR / "system.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        remediation_handler = logging.handlers.RotatingFileHandler(
            LOGS_DIR / "remediation.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        remediation_handler.addFilter(logging.Filter("vulnmngsys.remediation"))
        remediation_handler.setLevel(logging.INFO)
        remediation_handler.setFormatter(formatter)
        logger.addHandler(remediation_handler)
    except OSError as exc:
        logger.warning("File logging disabled: %s", exc)

    return logger


logger = setup_system_logger()
