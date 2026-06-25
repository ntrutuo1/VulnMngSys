import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Sequence

from vulnmngsys_app.adapters.logging.system_logger import logger

ROOT_DIR = Path(os.getenv("VULNMNGSYS_ROOT") or Path(__file__).resolve().parents[2])
BACKUP_DIR = ROOT_DIR / "reports" / "backups"


class BackupManager:
    """Backs up and restores system configuration touched by remediation."""

    def __init__(self):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    def trigger_backup(
        self,
        selected_rule_ids: Sequence[str] | None = None,
        registry_paths: Sequence[str] | None = None,
    ) -> str:
        backup_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        current_backup_dir = self.backup_path(backup_id)
        current_backup_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Starting backup. ID=%s selected_rules=%s", backup_id, len(selected_rule_ids or []))

        self._backup_secedit(current_backup_dir)
        self._backup_auditpol(current_backup_dir)
        self._backup_registry(current_backup_dir, registry_paths or [])

        logger.info("Backup completed. Path=%s", current_backup_dir)
        return backup_id

    def backup_path(self, backup_id: str) -> Path:
        return BACKUP_DIR / backup_id

    def _backup_secedit(self, backup_dir: Path) -> None:
        output_file = backup_dir / "secedit_backup.inf"
        try:
            result = subprocess.run(
                ["secedit", "/export", "/cfg", str(output_file)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                logger.error("Secedit backup failed: %s", result.stderr)
        except Exception as exc:
            logger.error("Secedit backup exception: %s", exc)

    def _backup_auditpol(self, backup_dir: Path) -> None:
        output_file = backup_dir / "auditpol_backup.csv"
        try:
            result = subprocess.run(
                ["auditpol", "/backup", f"/file:{output_file}"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode != 0:
                logger.error("Auditpol backup failed: %s", result.stderr)
        except Exception as exc:
            logger.error("Auditpol backup exception: %s", exc)

    def _backup_registry(self, backup_dir: Path, registry_paths: Sequence[str]) -> None:
        normalized_paths = [_normalize_reg_path(path) for path in registry_paths]
        unique_paths = [path for path in dict.fromkeys(normalized_paths) if path]
        if not unique_paths:
            return

        registry_dir = backup_dir / "registry"
        registry_dir.mkdir(parents=True, exist_ok=True)
        for index, registry_path in enumerate(unique_paths, start=1):
            output_file = registry_dir / f"{index:03d}_{_safe_filename(registry_path)}.reg"
            try:
                result = subprocess.run(
                    ["reg", "export", registry_path, str(output_file), "/y"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != 0:
                    logger.error("Registry backup failed for %s: %s", registry_path, result.stderr)
            except Exception as exc:
                logger.error("Registry backup exception for %s: %s", registry_path, exc)

    def rollback_config(self, backup_id: str) -> bool:
        target_backup_dir = self.backup_path(backup_id)
        if not target_backup_dir.exists():
            logger.error("Backup ID not found: %s", backup_id)
            return False

        logger.warning("Starting rollback from backup ID=%s", backup_id)
        success = True

        registry_dir = target_backup_dir / "registry"
        if registry_dir.exists():
            for reg_file in sorted(registry_dir.glob("*.reg")):
                try:
                    result = subprocess.run(
                        ["reg", "import", str(reg_file)],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                    if result.returncode != 0:
                        logger.error("Registry rollback failed for %s: %s", reg_file, result.stderr)
                        success = False
                except Exception as exc:
                    logger.error("Registry rollback exception for %s: %s", reg_file, exc)
                    success = False

        secedit_file = target_backup_dir / "secedit_backup.inf"
        if secedit_file.exists():
            db_path = target_backup_dir / "temp_rollback.sdb"
            try:
                result = subprocess.run(
                    [
                        "secedit",
                        "/configure",
                        "/db",
                        str(db_path),
                        "/cfg",
                        str(secedit_file),
                        "/areas",
                        "SECURITYPOLICY",
                        "USER_RIGHTS",
                    ],
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != 0:
                    success = False
            except Exception as exc:
                logger.error("Secedit rollback exception: %s", exc)
                success = False

        auditpol_file = target_backup_dir / "auditpol_backup.csv"
        if auditpol_file.exists():
            try:
                result = subprocess.run(
                    ["auditpol", "/restore", f"/file:{auditpol_file}"],
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != 0:
                    success = False
            except Exception as exc:
                logger.error("Auditpol rollback exception: %s", exc)
                success = False

        logger.info("Rollback completed. success=%s", success)
        return success


def _normalize_reg_path(path: str) -> str:
    text = str(path or "").strip().replace("/", "\\")
    if not text:
        return ""
    if ":\\" in text:
        hive, subkey = text.split(":\\", 1)
        text = f"{hive}\\{subkey}"
    aliases = {
        "HKEY_LOCAL_MACHINE": "HKLM",
        "HKEY_CURRENT_USER": "HKCU",
        "HKEY_USERS": "HKU",
        "HKEY_CLASSES_ROOT": "HKCR",
        "HKEY_CURRENT_CONFIG": "HKCC",
    }
    first, _, rest = text.partition("\\")
    hive = aliases.get(first.upper(), first)
    if not hive.upper().startswith("HK"):
        return ""
    return f"{hive}\\{rest}" if rest else hive


def _safe_filename(value: str) -> str:
    filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return filename[:120] or "registry"


backup_manager = BackupManager()
