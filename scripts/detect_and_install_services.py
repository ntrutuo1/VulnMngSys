from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vulnmngsys_app.platform_probe import detect_host_family, detect_host_version, list_service_versions

SERVICES = ["ssh", "apache-http", "apache-tomcat"]
APACHE_LAYOUTS = ["auto", "xampp", "standalone"]


def _print_header() -> None:
    print("VulnMngSys Service Version Probe")
    print(f"Host Family : {detect_host_family()}")
    print(f"Host Version: {detect_host_version()}")
    print("")


def _print_hits(service: str, hits: list[dict[str, str]]) -> None:
    print(f"[{service}]")
    if not hits:
        print("  - Not detected")
        print("")
        return

    for idx, hit in enumerate(hits, start=1):
        print(f"  {idx}. version={hit['version']}")
        print(f"     source : {hit['source']}")
        print(f"     command: {hit['command']}")
    print("")


def _run_command(command: list[str]) -> bool:
    try:
        completed = subprocess.run(command, check=False)
    except OSError as exc:
        print(f"Failed to run command: {' '.join(command)}")
        print(f"Reason: {exc}")
        return False

    if completed.returncode != 0:
        print(f"Command failed ({completed.returncode}): {' '.join(command)}")
        return False
    return True


def _has_package_tool(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def _linux_install_command(service: str) -> list[str] | None:
    if _has_package_tool("apt-get"):
        if service == "ssh":
            return ["sudo", "apt-get", "install", "-y", "openssh-server"]
        if service == "apache-http":
            return ["sudo", "apt-get", "install", "-y", "apache2"]
        if service == "apache-tomcat":
            return ["sudo", "apt-get", "install", "-y", "tomcat10"]

    if _has_package_tool("dnf"):
        if service == "ssh":
            return ["sudo", "dnf", "install", "-y", "openssh-server"]
        if service == "apache-http":
            return ["sudo", "dnf", "install", "-y", "httpd"]
        if service == "apache-tomcat":
            return ["sudo", "dnf", "install", "-y", "tomcat"]

    if _has_package_tool("yum"):
        if service == "ssh":
            return ["sudo", "yum", "install", "-y", "openssh-server"]
        if service == "apache-http":
            return ["sudo", "yum", "install", "-y", "httpd"]
        if service == "apache-tomcat":
            return ["sudo", "yum", "install", "-y", "tomcat"]

    if _has_package_tool("pacman"):
        if service == "ssh":
            return ["sudo", "pacman", "-S", "--noconfirm", "openssh"]
        if service == "apache-http":
            return ["sudo", "pacman", "-S", "--noconfirm", "apache"]
        if service == "apache-tomcat":
            return ["sudo", "pacman", "-S", "--noconfirm", "tomcat10"]

    return None


def _windows_install_command(service: str) -> list[str] | None:
    if service == "ssh":
        return [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Start-Service sshd; Set-Service -Name sshd -StartupType Automatic",
        ]

    # Apache HTTPD and Tomcat are covered by XAMPP on Windows.
    if service in {"apache-http", "apache-tomcat"}:
        return [
            "winget",
            "install",
            "--id",
            "ApacheFriends.Xampp.8.2",
            "-e",
            "--accept-source-agreements",
            "--accept-package-agreements",
        ]

    return None


def _install_service(service: str) -> bool:
    family = detect_host_family()
    command: list[str] | None = None

    if family == "windows":
        command = _windows_install_command(service)
    elif family == "linux":
        command = _linux_install_command(service)

    if not command:
        print(f"No automatic installer for service={service} on host family={family}")
        return False

    print(f"Installing missing service '{service}'...")
    print(f"Run: {' '.join(command)}")
    return _run_command(command)


def _confirm_install(missing_services: Iterable[str], auto_yes: bool) -> bool:
    missing_list = list(missing_services)
    if not missing_list:
        return False

    if auto_yes:
        return True

    print("Missing services detected:")
    for item in missing_list:
        print(f"- {item}")

    answer = input("Install missing services automatically? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect and optionally install SSH/Apache/Tomcat services")
    parser.add_argument(
        "--services",
        nargs="+",
        choices=SERVICES,
        default=SERVICES,
        help="Services to probe",
    )
    parser.add_argument(
        "--install-missing",
        action="store_true",
        help="Attempt to install services that are not detected",
    )
    parser.add_argument(
        "--apache-layout",
        choices=APACHE_LAYOUTS,
        default="auto",
        help="Apache detection mode (auto checks both XAMPP and standalone)",
    )
    parser.add_argument(
        "--xampp-root",
        default=None,
        help="Custom XAMPP/LAMPP root path (example: C:/xampp or /opt/lampp)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt when --install-missing is enabled",
    )
    args = parser.parse_args()

    _print_header()

    hits_by_service: dict[str, list[dict[str, str]]] = {}
    for service in args.services:
        hits = list_service_versions(
            service,
            apache_layout=args.apache_layout,
            xampp_root=args.xampp_root,
        )
        hits_by_service[service] = hits
        _print_hits(service, hits)

    missing = [service for service, hits in hits_by_service.items() if not hits]

    if args.install_missing and _confirm_install(missing, args.yes):
        for service in missing:
            _install_service(service)

        print("")
        print("Re-check after installation:")
        for service in missing:
            _print_hits(
                service,
                list_service_versions(
                    service,
                    apache_layout=args.apache_layout,
                    xampp_root=args.xampp_root,
                ),
            )

    if missing:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
