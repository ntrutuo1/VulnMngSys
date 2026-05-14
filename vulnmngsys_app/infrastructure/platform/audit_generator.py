"""Auto-generate audit.inf security policy export for Windows Server."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def get_audit_inf_path() -> Path:
    """Get the standard temp path for audit.inf."""
    temp_dir = os.environ.get("TEMP") or os.environ.get("TMP") or "C:\\Windows\\Temp"
    return Path(temp_dir) / "audit.inf"


def audit_inf_exists() -> bool:
    """Check if audit.inf already exists."""
    return get_audit_inf_path().exists()


def generate_audit_inf() -> tuple[bool, str]:
    """
    Generate audit.inf by running secedit command.
    
    Returns:
        (success: bool, message: str)
    """
    audit_path = get_audit_inf_path()
    
    # If already exists, no need to regenerate
    if audit_path.exists():
        return True, f"audit.inf already exists at {audit_path}"
    
    # Require admin privileges
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False
    
    if not is_admin:
        return False, (
            "Cannot generate audit.inf: Administrator privileges required.\n"
            "Please run this application as Administrator."
        )
    
    # Run secedit command to export security policy
    try:
        cmd = [
            "secedit.exe",
            "/export",
            "/cfg",
            str(audit_path),
            "/areas",
            "SECURITYPOLICY",
        ]
        
        # Use subprocess with proper error handling
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            return False, (
                f"secedit failed with code {result.returncode}:\n{error_msg}\n\n"
                f"Try running manually:\n"
                f"  secedit /export /cfg %TEMP%\\audit.inf /areas SECURITYPOLICY"
            )
        
        # Verify the file was created
        if not audit_path.exists():
            return False, (
                f"secedit completed but audit.inf was not created at:\n{audit_path}\n\n"
                f"Verify TEMP directory is writable and try again."
            )
        
        return True, f"Successfully generated audit.inf at {audit_path}"
    
    except subprocess.TimeoutExpired:
        return False, "secedit command timed out (30 seconds)"
    except FileNotFoundError:
        return False, (
            "secedit.exe not found. This utility requires Windows Server.\n"
            "If this is a custom build, ensure secedit is available in PATH."
        )
    except Exception as exc:
        return False, f"Error generating audit.inf: {exc}"


def ensure_audit_inf() -> tuple[bool, str]:
    """
    Ensure audit.inf exists, generating it if needed.
    
    Returns:
        (success: bool, message: str)
    """
    if audit_inf_exists():
        return True, f"audit.inf found at {get_audit_inf_path()}"
    
    return generate_audit_inf()
