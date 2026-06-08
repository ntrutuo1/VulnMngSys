import subprocess
import winreg
from typing import Any, Dict, List, Tuple
from domain.protocols import SystemCollector
from infrastructure.logging.system_logger import logger

def _get_registry_root(hive_name: str):
    hive = hive_name.upper().strip()
    if hive in {"HKLM", "HKEY_LOCAL_MACHINE"}:
        return winreg.HKEY_LOCAL_MACHINE
    if hive in {"HKCU", "HKEY_CURRENT_USER"}:
        return winreg.HKEY_CURRENT_USER
    if hive in {"HKU", "HKEY_USERS"}:
        return winreg.HKEY_USERS
    if hive in {"HKCR", "HKEY_CLASSES_ROOT"}:
        return winreg.HKEY_CLASSES_ROOT
    if hive in {"HKCC", "HKEY_CURRENT_CONFIG"}:
        return winreg.HKEY_CURRENT_CONFIG
    return winreg.HKEY_LOCAL_MACHINE

class WindowsCollector(SystemCollector):
    """Windows implementation of SystemCollector."""
    
    def __init__(self):
        self._secedit_cache = None
        self._user_rights_cache = None
        self._audit_policy_cache = None

    def get_registry_value(self, hive: str, key: str, value_name: str) -> Tuple[Any, str]:
        root = _get_registry_root(hive)
        try:
            with winreg.OpenKey(root, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as hkey:
                val, reg_type = winreg.QueryValueEx(hkey, value_name)
                # Convert type to string representation
                type_str = "Unknown"
                if reg_type == winreg.REG_DWORD: type_str = "REG_DWORD"
                elif reg_type == winreg.REG_SZ: type_str = "REG_SZ"
                elif reg_type == winreg.REG_MULTI_SZ: type_str = "REG_MULTI_SZ"
                
                return val, type_str
        except FileNotFoundError:
            return None, "NotFound"
        except Exception as e:
            logger.error(f"Lỗi đọc Registry {hive}\\{key}\\{value_name}: {e}")
            return None, "Error"

    def run_powershell(self, command: str, timeout: int = 60) -> str:
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            logger.error(f"Lệnh PowerShell bị timeout sau {timeout}s: {command[:50]}...")
            return ""
        except Exception as e:
            logger.error(f"Lỗi chạy PowerShell: {e}")
            return ""

    def _ensure_cache(self):
        if self._secedit_cache is None:
            from app_bootstrap.scanflow.json_rule_engine import _load_snapshots
            logger.info("Đang thu thập Snapshot từ Secedit và Auditpol...")
            snapshots = _load_snapshots()
            self._secedit_cache = snapshots.security_policy
            self._user_rights_cache = snapshots.user_rights
            self._audit_policy_cache = snapshots.audit_policy

    def get_secedit_policy(self) -> Dict[str, str]:
        self._ensure_cache()
        return self._secedit_cache

    def get_user_rights(self) -> Dict[str, List[str]]:
        self._ensure_cache()
        return self._user_rights_cache

    def get_audit_policy(self) -> Dict[str, str]:
        self._ensure_cache()
        return self._audit_policy_cache

