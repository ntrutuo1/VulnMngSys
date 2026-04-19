from __future__ import annotations

from ..common import make_directive_check
from ...models import ModuleDefinition, RuleCheck


def linux_ssh_paths() -> list[str]:
    return ["/etc/ssh/sshd_config"]


def windows_ssh_paths() -> list[str]:
    return [r"C:\ProgramData\ssh\sshd_config"]


def macos_ssh_paths() -> list[str]:
    return ["/etc/ssh/sshd_config"]


def build_ssh_checks(prefix: str) -> list[RuleCheck]:
    key = "ssh"
    return [
        make_directive_check(f"{prefix}-001", "Disable direct root login", "critical", key, "PermitRootLogin", "no"),
        make_directive_check(f"{prefix}-002", "Disallow empty passwords", "critical", key, "PermitEmptyPasswords", "no"),
        make_directive_check(f"{prefix}-003", "Limit auth retries", "high", key, "MaxAuthTries", "4"),
        make_directive_check(f"{prefix}-004", "Disable host-based auth", "high", key, "HostbasedAuthentication", "no"),
        make_directive_check(f"{prefix}-005", "Disable user environment overrides", "high", key, "PermitUserEnvironment", "no"),
        make_directive_check(f"{prefix}-006", "Enable PAM", "medium", key, "UsePAM", "yes"),
        make_directive_check(f"{prefix}-007", "Set keep-alive interval", "medium", key, "ClientAliveInterval", "15"),
        make_directive_check(f"{prefix}-008", "Set keep-alive max count", "medium", key, "ClientAliveCountMax", "3"),
        make_directive_check(f"{prefix}-009", "Set login grace timeout", "medium", key, "LoginGraceTime", "60"),
        make_directive_check(f"{prefix}-010", "Disable forwarding", "high", key, "DisableForwarding", "yes"),
        make_directive_check(f"{prefix}-011", "Set legal banner", "low", key, "Banner", "/etc/issue.net"),
    ]


def build_ssh_module(
    module_id: str,
    os_family: str,
    os_version: str,
    display_name: str,
    rules_source_file: str,
    config_paths: dict[str, list[str]],
    prefix: str,
) -> ModuleDefinition:
    return ModuleDefinition(
        module_id=module_id,
        os_family=os_family,
        os_version=os_version,
        service_type="ssh",
        display_name=display_name,
        rules_source_file=rules_source_file,
        config_paths=config_paths,
        checks=build_ssh_checks(prefix),
    )
