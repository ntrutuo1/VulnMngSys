import os
import sys
from pathlib import Path


if os.environ.get("VMS_APP_ROOT"):
    ROOT_DIR = Path(os.environ["VMS_APP_ROOT"])
elif getattr(sys, "frozen", False):
    executable_dir = Path(sys.executable).resolve().parent
    ROOT_DIR = executable_dir.parent if executable_dir.name == "backend_dist" else executable_dir
else:
    ROOT_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = Path(os.environ.get("VMS_DATA_DIR", ROOT_DIR))
WEB_DIR = ROOT_DIR / "web"
RULES_DIR = ROOT_DIR / "rules"
SEED_DATABASE_PATH = ROOT_DIR / "vulnmngsys.sqlite3"
DATABASE_PATH = DATA_DIR / "vulnmngsys.sqlite3"
WINDOWS_CVE_DATASET_PATH = ROOT_DIR / "windows_cve_dataset.json"

# Metasploit is an external dependency. It is not bundled into the installer.
env_msf_root = os.environ.get("VMS_MSF_ROOT")
MSF_ROOT = Path(env_msf_root) if env_msf_root else Path("E:/VulnMngApp/Tools/metasploit-framework")
METASPLOIT_FRAMEWORK_DIR = MSF_ROOT / "embedded" / "framework"
MSFCONSOLE_PATH = MSF_ROOT / "bin" / "msfconsole.bat"
MSFRPCD_PATH = MSF_ROOT / "bin" / "msfrpcd.bat"
MSFRPC_HOST = os.environ.get("VMS_MSF_RPC_HOST", "127.0.0.1")
MSFRPC_PORT = int(os.environ.get("VMS_MSF_RPC_PORT", "55552"))
MSFRPC_USER = os.environ.get("VMS_MSF_RPC_USER", "msf")
MSFRPC_PASS = os.environ.get("VMS_MSF_RPC_PASS", "vulnmngsys")
