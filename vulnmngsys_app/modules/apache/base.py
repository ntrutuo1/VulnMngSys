from __future__ import annotations

from ...models import ModuleDefinition, RuleCheck
from ..common import contains_xml_predicate, make_directive_check


def linux_apache_paths() -> list[str]:
    return [
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
    ]


def windows_apache_paths() -> list[str]:
    return [r"C:\Apache24\conf\httpd.conf"]


def macos_apache_paths() -> list[str]:
    return ["/etc/apache2/httpd.conf"]


def linux_tomcat_paths() -> dict[str, list[str]]:
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


def windows_tomcat_paths() -> dict[str, list[str]]:
    return {
        "server": [r"C:\Tomcat\conf\server.xml"],
        "web": [r"C:\Tomcat\conf\web.xml"],
        "context": [r"C:\Tomcat\conf\context.xml"],
    }


def macos_tomcat_paths() -> dict[str, list[str]]:
    return {
        "server": ["/usr/local/opt/tomcat/conf/server.xml"],
        "web": ["/usr/local/opt/tomcat/conf/web.xml"],
        "context": ["/usr/local/opt/tomcat/conf/context.xml"],
    }


def build_apache_http_checks(prefix: str) -> list[RuleCheck]:
    key = "apache"
    return [
        make_directive_check(f"{prefix}-001", "Hide version details", "high", key, "ServerTokens", "Prod"),
        make_directive_check(f"{prefix}-002", "Disable server signature", "medium", key, "ServerSignature", "Off"),
        make_directive_check(f"{prefix}-003", "Disable TRACE", "high", key, "TraceEnable", "off"),
        make_directive_check(f"{prefix}-004", "Limit keepalive requests", "medium", key, "MaxKeepAliveRequests", "100"),
        make_directive_check(f"{prefix}-005", "Set keepalive timeout", "medium", key, "KeepAliveTimeout", "15"),
        make_directive_check(f"{prefix}-006", "Set request timeout", "medium", key, "Timeout", "10"),
        make_directive_check(f"{prefix}-007", "Limit request line", "medium", key, "LimitRequestLine", "8190"),
        make_directive_check(f"{prefix}-008", "Limit request fields", "medium", key, "LimitRequestFields", "100"),
        make_directive_check(f"{prefix}-009", "Limit request field size", "medium", key, "LimitRequestFieldsize", "8190"),
        make_directive_check(f"{prefix}-010", "Limit request body", "high", key, "LimitRequestBody", "102400"),
    ]


def build_tomcat_checks(prefix: str) -> list[RuleCheck]:
    return [
        contains_xml_predicate(
            f"{prefix}-001",
            "Disable shutdown port",
            "critical",
            "server",
            lambda raw_xml: "<Server" in raw_xml and 'port="-1"' in raw_xml,
            "Shutdown port disabled",
            "Missing <Server port=\"-1\">",
        ),
        contains_xml_predicate(
            f"{prefix}-002",
            "Harden connector methods and headers",
            "high",
            "server",
            lambda raw_xml: all(
                item in raw_xml
                for item in ['allowTrace="false"', 'xpoweredBy="false"', 'maxHttpHeaderSize="8192"']
            ),
            "Connector hardening fields found",
            "Connector hardening fields missing",
        ),
        contains_xml_predicate(
            f"{prefix}-003",
            "Mask server header",
            "medium",
            "server",
            lambda raw_xml: 'server="I am a teapot"' in raw_xml or 'server=""' in raw_xml,
            "Server header masked",
            "Server header masking missing",
        ),
        contains_xml_predicate(
            f"{prefix}-004",
            "Safe global error page",
            "high",
            "web",
            lambda raw_xml: "java.lang.Throwable" in raw_xml and "/error.jsp" in raw_xml,
            "Throwable error page mapping exists",
            "Throwable error-page mapping missing",
        ),
        contains_xml_predicate(
            f"{prefix}-005",
            "Default servlet readonly and no listing",
            "high",
            "web",
            lambda raw_xml: (
                "<servlet-name>default</servlet-name>" in raw_xml
                and "<param-name>readonly</param-name>" in raw_xml
                and "<param-value>true</param-value>" in raw_xml
                and "<param-name>listings</param-name>" in raw_xml
                and raw_xml.count("<param-value>false</param-value>") >= 1
            ),
            "Default servlet hardened",
            "Default servlet hardening missing",
        ),
        contains_xml_predicate(
            f"{prefix}-006",
            "Disable cross-context and symlink",
            "medium",
            "context",
            lambda raw_xml: 'crossContext="false"' in raw_xml and 'allowLinking="false"' in raw_xml,
            "Context restrictions found",
            "Context restrictions missing",
        ),
    ]


def build_apache_http_module(
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
        service_type="apache-http",
        display_name=display_name,
        rules_source_file=rules_source_file,
        config_paths=config_paths,
        checks=build_apache_http_checks(prefix),
    )


def build_tomcat_module(
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
        service_type="apache-tomcat",
        display_name=display_name,
        rules_source_file=rules_source_file,
        config_paths=config_paths,
        checks=build_tomcat_checks(prefix),
    )
