from __future__ import annotations

from pathlib import Path

from .models import ModuleDefinition, RuleCheck


SEVERITY_WEIGHT = {
    "low": 1,
    "medium": 4,
    "high": 7,
    "critical": 10,
}


def _make_directive_check(
    code: str,
    title: str,
    severity: str,
    config_file_key: str,
    directive: str,
    expected_value: str,
) -> RuleCheck:
    expected_normalized = expected_value.strip().lower()

    def evaluate(raw_text: str) -> tuple[bool, str]:
        effective = _extract_last_directive_value(raw_text, directive)
        if effective is None:
            return False, f"Missing directive: {directive}"
        actual = " ".join(effective.split()).lower()
        if actual != expected_normalized:
            return False, f"Expected '{directive} {expected_value}', got '{directive} {effective}'"
        return True, "Matched expected value"

    return RuleCheck(
        code=code,
        title=title,
        severity=severity,
        weight=SEVERITY_WEIGHT[severity.lower()],
        config_file_key=config_file_key,
        evaluator=evaluate,
    )


def _extract_last_directive_value(raw_text: str, directive: str) -> str | None:
    matched_value: str | None = None
    lookup = directive.lower()
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        content = stripped.split("#", 1)[0].strip()
        if not content:
            continue
        parts = content.split()
        if not parts:
            continue
        key = parts[0].lower()
        if key == lookup:
            matched_value = " ".join(parts[1:]).strip()
    return matched_value


def _contains_xml_predicate(
    code: str,
    title: str,
    severity: str,
    config_file_key: str,
    predicate,
    success_message: str,
    failure_message: str,
) -> RuleCheck:
    def evaluate(raw_text: str) -> tuple[bool, str]:
        passed = predicate(raw_text)
        if passed:
            return True, success_message
        return False, failure_message

    return RuleCheck(
        code=code,
        title=title,
        severity=severity,
        weight=SEVERITY_WEIGHT[severity.lower()],
        config_file_key=config_file_key,
        evaluator=evaluate,
    )


def _server_port_disabled(raw_xml: str) -> bool:
    return "<Server" in raw_xml and 'port="-1"' in raw_xml


def _connector_security_headers(raw_xml: str) -> bool:
    checks = [
        'allowTrace="false"',
        'xpoweredBy="false"',
        'maxHttpHeaderSize="8192"',
    ]
    return all(item in raw_xml for item in checks)


def _connector_server_masking(raw_xml: str) -> bool:
    return 'server="I am a teapot"' in raw_xml or 'server=""' in raw_xml


def _web_error_page(raw_xml: str) -> bool:
    return "java.lang.Throwable" in raw_xml and "/error.jsp" in raw_xml


def _default_servlet_hardening(raw_xml: str) -> bool:
    return (
        "<servlet-name>default</servlet-name>" in raw_xml
        and "<param-name>readonly</param-name>" in raw_xml
        and "<param-value>true</param-value>" in raw_xml
        and "<param-name>listings</param-name>" in raw_xml
        and raw_xml.count("<param-value>false</param-value>") >= 1
    )


def _context_restrictions(raw_xml: str) -> bool:
    return 'crossContext="false"' in raw_xml and 'allowLinking="false"' in raw_xml


def _linux_ssh_paths() -> list[str]:
    return ["/etc/ssh/sshd_config"]


def _windows_ssh_paths() -> list[str]:
    return [r"C:\ProgramData\ssh\sshd_config"]


def _linux_apache_paths() -> list[str]:
    return [
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
    ]


def _windows_apache_paths() -> list[str]:
    return [r"C:\Apache24\conf\httpd.conf"]


def _mac_apache_paths() -> list[str]:
    return ["/etc/apache2/httpd.conf"]


def _linux_tomcat_paths() -> dict[str, list[str]]:
    return {
        "server": [
            "/etc/tomcat/server.xml",
            "/opt/tomcat/conf/server.xml",
            "/usr/share/tomcat/conf/server.xml",
        ],
        "web": [
            "/etc/tomcat/web.xml",
            "/opt/tomcat/conf/web.xml",
            "/usr/share/tomcat/conf/web.xml",
        ],
        "context": [
            "/etc/tomcat/context.xml",
            "/opt/tomcat/conf/context.xml",
            "/usr/share/tomcat/conf/context.xml",
        ],
    }


def _windows_tomcat_paths() -> dict[str, list[str]]:
    return {
        "server": [r"C:\Tomcat\conf\server.xml"],
        "web": [r"C:\Tomcat\conf\web.xml"],
        "context": [r"C:\Tomcat\conf\context.xml"],
    }


def _mac_tomcat_paths() -> dict[str, list[str]]:
    return {
        "server": ["/usr/local/opt/tomcat/conf/server.xml"],
        "web": ["/usr/local/opt/tomcat/conf/web.xml"],
        "context": ["/usr/local/opt/tomcat/conf/context.xml"],
    }


def _build_ssh_checks(prefix: str) -> list[RuleCheck]:
    key = "ssh"
    return [
        _make_directive_check(f"{prefix}-001", "Disable direct root login", "critical", key, "PermitRootLogin", "no"),
        _make_directive_check(f"{prefix}-002", "Disallow empty passwords", "critical", key, "PermitEmptyPasswords", "no"),
        _make_directive_check(f"{prefix}-003", "Limit auth retries", "high", key, "MaxAuthTries", "4"),
        _make_directive_check(f"{prefix}-004", "Disable host-based auth", "high", key, "HostbasedAuthentication", "no"),
        _make_directive_check(f"{prefix}-005", "Disable user environment overrides", "high", key, "PermitUserEnvironment", "no"),
        _make_directive_check(f"{prefix}-006", "Enable PAM", "medium", key, "UsePAM", "yes"),
        _make_directive_check(f"{prefix}-007", "Set keep-alive interval", "medium", key, "ClientAliveInterval", "15"),
        _make_directive_check(f"{prefix}-008", "Set keep-alive max count", "medium", key, "ClientAliveCountMax", "3"),
        _make_directive_check(f"{prefix}-009", "Set login grace timeout", "medium", key, "LoginGraceTime", "60"),
        _make_directive_check(f"{prefix}-010", "Disable forwarding", "high", key, "DisableForwarding", "yes"),
        _make_directive_check(f"{prefix}-011", "Set legal banner", "low", key, "Banner", "/etc/issue.net"),
    ]


def _build_apache_http_checks(prefix: str) -> list[RuleCheck]:
    key = "apache"
    return [
        _make_directive_check(f"{prefix}-001", "Hide version details", "high", key, "ServerTokens", "Prod"),
        _make_directive_check(f"{prefix}-002", "Disable server signature", "medium", key, "ServerSignature", "Off"),
        _make_directive_check(f"{prefix}-003", "Disable TRACE", "high", key, "TraceEnable", "off"),
        _make_directive_check(f"{prefix}-004", "Limit keepalive requests", "medium", key, "MaxKeepAliveRequests", "100"),
        _make_directive_check(f"{prefix}-005", "Set keepalive timeout", "medium", key, "KeepAliveTimeout", "15"),
        _make_directive_check(f"{prefix}-006", "Set request timeout", "medium", key, "Timeout", "10"),
        _make_directive_check(f"{prefix}-007", "Limit request line", "medium", key, "LimitRequestLine", "8190"),
        _make_directive_check(f"{prefix}-008", "Limit request fields", "medium", key, "LimitRequestFields", "100"),
        _make_directive_check(f"{prefix}-009", "Limit request field size", "medium", key, "LimitRequestFieldsize", "8190"),
        _make_directive_check(f"{prefix}-010", "Limit request body", "high", key, "LimitRequestBody", "102400"),
    ]


def _build_tomcat_checks(prefix: str) -> list[RuleCheck]:
    return [
        _contains_xml_predicate(
            f"{prefix}-001",
            "Disable shutdown port",
            "critical",
            "server",
            _server_port_disabled,
            "Shutdown port disabled",
            "Missing <Server port=\"-1\">",
        ),
        _contains_xml_predicate(
            f"{prefix}-002",
            "Harden connector methods and headers",
            "high",
            "server",
            _connector_security_headers,
            "Connector hardening fields found",
            "Connector hardening fields missing",
        ),
        _contains_xml_predicate(
            f"{prefix}-003",
            "Mask server header",
            "medium",
            "server",
            _connector_server_masking,
            "Server header masked",
            "Server header masking missing",
        ),
        _contains_xml_predicate(
            f"{prefix}-004",
            "Safe global error page",
            "high",
            "web",
            _web_error_page,
            "Throwable error page mapping exists",
            "Throwable error-page mapping missing",
        ),
        _contains_xml_predicate(
            f"{prefix}-005",
            "Default servlet readonly and no listing",
            "high",
            "web",
            _default_servlet_hardening,
            "Default servlet hardened",
            "Default servlet hardening missing",
        ),
        _contains_xml_predicate(
            f"{prefix}-006",
            "Disable cross-context and symlink",
            "medium",
            "context",
            _context_restrictions,
            "Context restrictions found",
            "Context restrictions missing",
        ),
    ]


def _rules_file(name: str) -> str:
    return str((Path(__file__).resolve().parents[1] / "rules" / name).resolve())


def load_modules() -> list[ModuleDefinition]:
    linux_ssh_22 = ModuleDefinition(
        module_id="linux-ubuntu22-ssh",
        os_family="linux",
        os_version="ubuntu-22.04",
        service_type="ssh",
        display_name="Ubuntu 22.04 - SSH Server",
        rules_source_file=_rules_file("SSH_Ubuntu_22.04.txt"),
        config_paths={"ssh": _linux_ssh_paths()},
        checks=_build_ssh_checks("U22SSH"),
    )

    linux_ssh_24 = ModuleDefinition(
        module_id="linux-ubuntu24-ssh",
        os_family="linux",
        os_version="ubuntu-24.04",
        service_type="ssh",
        display_name="Ubuntu 24.04 - SSH Server",
        rules_source_file=_rules_file("SSH_Ubuntu_24.04.txt"),
        config_paths={"ssh": _linux_ssh_paths()},
        checks=_build_ssh_checks("U24SSH"),
    )

    linux_apache_http = ModuleDefinition(
        module_id="linux-generic-apache-http",
        os_family="linux",
        os_version="generic",
        service_type="apache-http",
        display_name="Linux - Apache HTTP Server 2.4",
        rules_source_file=_rules_file("Apache_HTTP_server.txt"),
        config_paths={"apache": _linux_apache_paths()},
        checks=_build_apache_http_checks("APHTTP"),
    )

    linux_tomcat = ModuleDefinition(
        module_id="linux-generic-tomcat",
        os_family="linux",
        os_version="generic",
        service_type="apache-tomcat",
        display_name="Linux - Apache Tomcat 7/8/9/10/10.1",
        rules_source_file=_rules_file("Apache_Tomcat.txt"),
        config_paths=_linux_tomcat_paths(),
        checks=_build_tomcat_checks("APTOM"),
    )

    windows_ssh = ModuleDefinition(
        module_id="windows-11-ssh",
        os_family="windows",
        os_version="windows-11",
        service_type="ssh",
        display_name="Windows 11 - OpenSSH Server",
        rules_source_file=_rules_file("SSH_Ubuntu_24.04.txt"),
        config_paths={"ssh": _windows_ssh_paths()},
        checks=_build_ssh_checks("WINSSH"),
    )

    windows_apache = ModuleDefinition(
        module_id="windows-generic-apache-http",
        os_family="windows",
        os_version="generic",
        service_type="apache-http",
        display_name="Windows - Apache HTTP Server 2.4",
        rules_source_file=_rules_file("Apache_HTTP_server.txt"),
        config_paths={"apache": _windows_apache_paths()},
        checks=_build_apache_http_checks("WINHTTP"),
    )

    windows_tomcat = ModuleDefinition(
        module_id="windows-generic-tomcat",
        os_family="windows",
        os_version="generic",
        service_type="apache-tomcat",
        display_name="Windows - Apache Tomcat 10.1",
        rules_source_file=_rules_file("Apache_Tomcat.txt"),
        config_paths=_windows_tomcat_paths(),
        checks=_build_tomcat_checks("WINTOM"),
    )

    mac_ssh = ModuleDefinition(
        module_id="macos-14-ssh",
        os_family="macos",
        os_version="macos-14",
        service_type="ssh",
        display_name="macOS 14 - OpenSSH",
        rules_source_file=_rules_file("SSH_Ubuntu_24.04.txt"),
        config_paths={"ssh": ["/etc/ssh/sshd_config"]},
        checks=_build_ssh_checks("MACSSH"),
    )

    mac_apache = ModuleDefinition(
        module_id="macos-generic-apache-http",
        os_family="macos",
        os_version="generic",
        service_type="apache-http",
        display_name="macOS - Apache HTTP Server",
        rules_source_file=_rules_file("Apache_HTTP_server.txt"),
        config_paths={"apache": _mac_apache_paths()},
        checks=_build_apache_http_checks("MACHTTP"),
    )

    mac_tomcat = ModuleDefinition(
        module_id="macos-generic-tomcat",
        os_family="macos",
        os_version="generic",
        service_type="apache-tomcat",
        display_name="macOS - Apache Tomcat",
        rules_source_file=_rules_file("Apache_Tomcat.txt"),
        config_paths=_mac_tomcat_paths(),
        checks=_build_tomcat_checks("MACTOM"),
    )

    return [
        linux_ssh_22,
        linux_ssh_24,
        linux_apache_http,
        linux_tomcat,
        windows_ssh,
        windows_apache,
        windows_tomcat,
        mac_ssh,
        mac_apache,
        mac_tomcat,
    ]
