from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path


def detect_host_family() -> str:
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system == "darwin":
        return "macos"
    return "linux"


def detect_host_version() -> str:
    family = detect_host_family()
    if family == "windows":
        release = platform.release().strip() or "unknown"
        return f"windows-{release}"
    if family == "macos":
        version = platform.mac_ver()[0].strip()
        if version:
            major = version.split(".")[0]
            return f"macos-{major}"
        return "macos-generic"

    os_release = Path("/etc/os-release")
    if os_release.exists():
        content = os_release.read_text(encoding="utf-8", errors="ignore")
        if "ubuntu" in content.lower() and "22.04" in content:
            return "ubuntu-22.04"
        if "ubuntu" in content.lower() and "24.04" in content:
            return "ubuntu-24.04"
    return "generic"


def _run_version_command(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError:
        return ""
    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    return output.strip()


def _extract_first_semver(text: str) -> str | None:
    # Accept 2.4.58, 9.7p1, 10.1.34-M1 and similar variants.
    match = re.search(r"\b\d+(?:\.\d+){1,3}(?:[a-zA-Z0-9\-_.]+)?\b", text)
    if not match:
        return None
    return match.group(0)


def detect_service_version(service_type: str) -> str | None:
    family = detect_host_family()

    if service_type == "ssh":
        text = _run_version_command(["ssh", "-V"])
        return _extract_first_semver(text)

    if service_type == "apache-http":
        commands: list[list[str]] = [["apache2", "-v"], ["httpd", "-v"], ["apachectl", "-v"]]
        if family == "windows":
            commands.insert(0, [r"C:\Apache24\bin\httpd.exe", "-v"])

        for command in commands:
            text = _run_version_command(command)
            version = _extract_first_semver(text)
            if version:
                return version
        return None

    if service_type == "apache-tomcat":
        commands: list[list[str]] = [
            ["catalina.sh", "version"],
            ["/usr/share/tomcat/bin/version.sh"],
            ["/opt/tomcat/bin/version.sh"],
        ]
        if family == "windows":
            commands = [[r"C:\Tomcat\bin\version.bat"]]

        for command in commands:
            text = _run_version_command(command)
            version = _extract_first_semver(text)
            if version:
                return version
        return None

    return None
