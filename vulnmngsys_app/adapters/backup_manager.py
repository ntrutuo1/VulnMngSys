import json
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
        self._backup_iis(current_backup_dir, backup_id)

        logger.info("Backup completed. Path=%s", current_backup_dir)
        return backup_id

    def createBackup(
        self,
        *,
        reason: str = "",
        selectedRules: Sequence[str] | None = None,
        registryPaths: Sequence[str] | None = None,
    ) -> str:
        backup_id = self.trigger_backup(selectedRules, registry_paths=registryPaths)
        metadata = {
            "backupId": backup_id,
            "reason": reason,
            "selectedRules": list(selectedRules or []),
            "createdAt": datetime.now().isoformat(),
        }
        (self.backup_path(backup_id) / "backup_metadata.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return backup_id

    def verifyBackup(self, backup_id: str) -> bool:
        path = self.backup_path(backup_id)
        if not path.exists() or not path.is_dir():
            return False
        return any(item.is_file() for item in path.rglob("*"))

    def listBackups(self) -> list[dict[str, str]]:
        backups: list[dict[str, str]] = []
        if not BACKUP_DIR.exists():
            return backups
        for path in sorted(BACKUP_DIR.iterdir(), reverse=True):
            if path.is_dir():
                backups.append({"backupId": path.name, "backupPath": str(path)})
        return backups

    def rollback(self, backup_id: str) -> bool:
        return self.rollback_config(backup_id)

    def verifyRollback(self, backup_id: str) -> bool:
        return self.backup_path(backup_id).exists()

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

    def _backup_iis(self, backup_dir: Path, backup_id: str) -> None:
        appcmd = _appcmd_path()
        if appcmd is None:
            return
        marker = backup_dir / "iis_backup_name.txt"
        backup_name = f"VulnMngSys_{backup_id}"
        try:
            result = subprocess.run(
                [str(appcmd), "add", "backup", backup_name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode == 0:
                marker.write_text(backup_name, encoding="utf-8")
            else:
                logger.error("IIS backup failed: %s", result.stderr)
        except Exception as exc:
            logger.error("IIS backup exception: %s", exc)

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

        iis_backup_name = target_backup_dir / "iis_backup_name.txt"
        appcmd = _appcmd_path()
        if iis_backup_name.exists() and appcmd is not None:
            try:
                result = subprocess.run(
                    [str(appcmd), "restore", "backup", iis_backup_name.read_text(encoding="utf-8").strip()],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                if result.returncode != 0:
                    logger.error("IIS rollback failed: %s", result.stderr)
                    success = False
            except Exception as exc:
                logger.error("IIS rollback exception: %s", exc)
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


def _appcmd_path() -> Path | None:
    windir = os.getenv("windir") or os.getenv("SystemRoot") or r"C:\Windows"
    candidate = Path(windir) / "System32" / "inetsrv" / "appcmd.exe"
    return candidate if candidate.exists() else None


backup_manager = BackupManager()
