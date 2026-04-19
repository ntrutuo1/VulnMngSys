from __future__ import annotations

import platform
import re
import subprocess
from pathlib import Path
from typing import TypedDict


class ServiceVersionHit(TypedDict):
    source: str
    command: str
    version: str


def _resolve_xampp_root(family: str, xampp_root: str | None) -> str:
    if xampp_root and xampp_root.strip():
        return xampp_root.strip()
    if family == "windows":
        return r"C:\xampp"
    return "/opt/lampp"


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


def _run_version_command(command: list[str], cwd: str | None = None) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, cwd=cwd)
    except OSError:
        return ""
    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    return output.strip()


def _run_powershell(script: str) -> str:
    return _run_version_command([
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ])


def _extract_first_semver(text: str) -> str | None:
    ssh_match = re.search(
        r"OpenSSH[^0-9]*([0-9]+(?:\.[0-9]+){1,3}(?:p[0-9]+)?)",
        text,
        re.IGNORECASE,
    )
    if ssh_match:
        return ssh_match.group(1)

    match = re.search(r"(?<!\d)\d+(?:\.\d+){1,3}(?:[a-zA-Z0-9\-_.]+)?", text)
    if not match:
        return None
    return match.group(0)


def _collect_versions(candidates: list[tuple[str, list[str], str | None]]) -> list[ServiceVersionHit]:
    hits: list[ServiceVersionHit] = []
    for source, command, cwd in candidates:
        text = _run_version_command(command, cwd=cwd)
        version = _extract_first_semver(text)
        if not version:
            continue
        display_command = " ".join(command)
        if cwd:
            display_command = f"cd {cwd} && {display_command}"
        hits.append(
            {
                "source": source,
                "command": display_command,
                "version": version,
            }
        )
    return hits


def list_service_versions(
    service_type: str,
    apache_layout: str = "auto",
    xampp_root: str | None = None,
) -> list[ServiceVersionHit]:
    family = detect_host_family()
    layout = apache_layout.strip().lower()
    if layout not in {"auto", "xampp", "standalone"}:
        layout = "auto"
    resolved_xampp_root = _resolve_xampp_root(family, xampp_root)

    if service_type == "ssh":
        candidates: list[tuple[str, list[str], str | None]] = [
            ("PATH:ssh", ["ssh", "-V"], None),
            ("PATH:sshd", ["sshd", "-V"], None),
        ]
        if family == "windows":
            candidates.extend(
                [
                    ("OpenSSH:ssh.exe", [r"C:\Windows\System32\OpenSSH\ssh.exe", "-V"], None),
                    ("OpenSSH:sshd.exe", [r"C:\Windows\System32\OpenSSH\sshd.exe", "-V"], None),
                ]
            )

        hits = _collect_versions(candidates)
        if hits:
            return hits

        if family == "windows":
            ps_text = _run_powershell("(Get-Command ssh -ErrorAction SilentlyContinue).Version.ToString()")
            version = _extract_first_semver(ps_text)
            if version:
                return [{"source": "PowerShell:Get-Command ssh", "command": "Get-Command ssh", "version": version}]
        return []

    if service_type == "apache-http":
        candidates: list[tuple[str, list[str], str | None]] = []
        if family == "windows":
            if layout in {"auto", "xampp"}:
                xampp_apache_bin = str(Path(resolved_xampp_root) / "apache" / "bin")
                candidates.extend(
                    [
                        ("XAMPP:httpd-bin", ["httpd.exe", "-v"], xampp_apache_bin),
                        ("XAMPP:httpd-fullpath", [str(Path(xampp_apache_bin) / "httpd.exe"), "-v"], None),
                    ]
                )
            if layout in {"auto", "standalone"}:
                candidates.extend(
                    [
                        ("Apache24", [r"C:\Apache24\bin\httpd.exe", "-v"], None),
                        ("ApacheFoundation", [r"C:\Program Files\Apache Software Foundation\Apache2.4\bin\httpd.exe", "-v"], None),
                        ("ApacheGroup", [r"C:\Program Files\Apache Group\Apache2\bin\httpd.exe", "-v"], None),
                        ("PATH:httpd", ["httpd", "-v"], None),
                    ]
                )
        else:
            if layout in {"auto", "xampp"}:
                lampp_apache_bin = str(Path(resolved_xampp_root) / "bin")
                candidates.extend(
                    [
                        ("LAMPP:httpd-bin", ["./httpd", "-v"], lampp_apache_bin),
                        ("LAMPP:httpd-fullpath", [str(Path(lampp_apache_bin) / "httpd"), "-v"], None),
                    ]
                )
            if layout in {"auto", "standalone"}:
                candidates.extend(
                    [
                        ("PATH:apache2", ["apache2", "-v"], None),
                        ("PATH:httpd", ["httpd", "-v"], None),
                        ("PATH:apachectl", ["apachectl", "-v"], None),
                    ]
                )

        hits = _collect_versions(candidates)
        if hits:
            return hits

        if family == "windows" and layout in {"auto", "standalone"}:
            ps_text = _run_powershell(
                "$svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -match '^Apache|httpd' } | Select-Object -First 1; "
                "if ($svc) { $svc.PathName }"
            )
            exe_match = re.search(r'[A-Za-z]:[^\"\n\r]+httpd\.exe', ps_text)
            if exe_match:
                exe_path = exe_match.group(0).strip()
                text = _run_version_command([exe_path, "-v"])
                version = _extract_first_semver(text)
                if version:
                    return [{"source": "Windows Service Path", "command": f"{exe_path} -v", "version": version}]
        return []

    if service_type == "apache-tomcat":
        candidates: list[tuple[str, list[str], str | None]] = []
        if family == "windows":
            if layout in {"auto", "xampp"}:
                xampp_tomcat_bin = str(Path(resolved_xampp_root) / "tomcat" / "bin")
                candidates.extend(
                    [
                        ("XAMPP:tomcat-bin", ["cmd", "/c", "version.bat"], xampp_tomcat_bin),
                        ("XAMPP:tomcat-catalina", ["cmd", "/c", "catalina.bat", "version"], xampp_tomcat_bin),
                    ]
                )
            if layout in {"auto", "standalone"}:
                candidates.extend(
                    [
                        ("Tomcat:C:/Tomcat", [r"C:\Tomcat\bin\version.bat"], None),
                        ("Tomcat 10.1", [r"C:\Program Files\Apache Software Foundation\Tomcat 10.1\bin\version.bat"], None),
                        ("Tomcat 9.0", [r"C:\Program Files\Apache Software Foundation\Tomcat 9.0\bin\version.bat"], None),
                        ("PATH:catalina.bat", ["catalina.bat", "version"], None),
                    ]
                )
        else:
            if layout in {"auto", "xampp"}:
                lampp_tomcat_bin = str(Path(resolved_xampp_root) / "tomcat" / "bin")
                candidates.extend(
                    [
                        ("LAMPP:tomcat-bin", ["./version.sh"], lampp_tomcat_bin),
                        ("LAMPP:tomcat-fullpath", [str(Path(lampp_tomcat_bin) / "version.sh")], None),
                    ]
                )
            if layout in {"auto", "standalone"}:
                candidates.extend(
                    [
                        ("PATH:catalina.sh", ["catalina.sh", "version"], None),
                        ("PATH:catalina", ["catalina", "version"], None),
                        ("Tomcat:/usr/share/tomcat/bin/version.sh", ["/usr/share/tomcat/bin/version.sh"], None),
                        ("Tomcat:/opt/tomcat/bin/version.sh", ["/opt/tomcat/bin/version.sh"], None),
                    ]
                )

        hits = _collect_versions(candidates)
        if hits:
            return hits

        if family == "windows" and layout in {"auto", "standalone"}:
            ps_text = _run_powershell(
                "$svc = Get-CimInstance Win32_Service | Where-Object { $_.Name -match 'Tomcat' } | Select-Object -First 1; "
                "if ($svc) { $svc.PathName }"
            )
            exe_match = re.search(r'[A-Za-z]:[^\"\n\r]+(?:tomcat\d*|tomcat)\d*\.exe', ps_text, re.IGNORECASE)
            if exe_match:
                exe_path = exe_match.group(0).strip()
                text = _run_version_command([exe_path, "//VS//"])
                version = _extract_first_semver(text)
                if version:
                    return [{"source": "Windows Service Path", "command": f"{exe_path} //VS//", "version": version}]
        return []

    return []


def detect_service_version(
    service_type: str,
    apache_layout: str = "auto",
    xampp_root: str | None = None,
) -> str | None:
    hits = list_service_versions(service_type, apache_layout=apache_layout, xampp_root=xampp_root)
    if not hits:
        return None
    return hits[0]["version"]
