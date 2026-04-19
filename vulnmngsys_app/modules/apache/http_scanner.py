from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ...models import RuleCheck


@dataclass(frozen=True)
class ApacheHttpRuleSpec:
    code: str
    title: str
    severity: str
    search: str
    baseline: str
    evaluator: Callable[[str], tuple[bool, str]]


def _active_lines(raw_text: str) -> list[str]:
    lines: list[str] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        content = line.split("#", 1)[0].rstrip()
        if content.strip():
            lines.append(content)
    return lines


def _active_text(raw_text: str) -> str:
    return "\n".join(_active_lines(raw_text))


def _has_pattern(raw_text: str, pattern: str, *, flags: int = re.IGNORECASE | re.MULTILINE | re.DOTALL) -> bool:
    return bool(re.search(pattern, _active_text(raw_text), flags))


def _directive_values(raw_text: str, directive: str) -> list[str]:
    values: list[str] = []
    pattern = re.compile(rf"^\s*{re.escape(directive)}\s+(.*?)\s*$", re.IGNORECASE)
    for line in _active_lines(raw_text):
        match = pattern.search(line)
        if match:
            values.append(match.group(1).strip())
    return values


def _bool_result(passed: bool, passed_text: str, failed_text: str) -> tuple[bool, str]:
    return passed, passed_text if passed else failed_text


def check_log_config_module(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*LoadModule\s+log_config_module\b"),
        "LoadModule log_config_module",
        "Cần có LoadModule log_config_module",
    )


def check_modules_disabled(raw_text: str, module_pattern: str, label: str) -> tuple[bool, str]:
    matched = _has_pattern(raw_text, rf"^\s*LoadModule\s+{module_pattern}\b")
    return _bool_result(
        not matched,
        f"{label} đã tắt",
        f"Tắt {label}",
    )


def check_user_not_privileged(raw_text: str) -> tuple[bool, str]:
    user_values = _directive_values(raw_text, "User")
    group_values = _directive_values(raw_text, "Group")

    privileged = {"root", "daemon", "_www", "www-data", "www"}
    user_ok = all(value.lower() not in privileged for value in user_values)
    group_ok = all(value.lower() not in privileged for value in group_values)

    if user_values and group_values:
        passed = user_ok and group_ok
        return _bool_result(
            passed,
            f"User/Group: {user_values[0]} / {group_values[0]}",
            f"Apache không được chạy bằng quyền root/daemon: User={user_values[0]}, Group={group_values[0]}",
        )

    return False, "Thiếu cấu hình User/Group an toàn"


def check_core_dump_disabled(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        not _has_pattern(raw_text, r"^\s*CoreDumpDirectory\b", flags=re.IGNORECASE | re.MULTILINE),
        "Không cấu hình CoreDumpDirectory",
        "Không nên cấu hình CoreDumpDirectory",
    )


def check_directory_root_denied(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"<Directory\s+/?>.*?Require\s+all\s+denied.*?</Directory>")
        or _has_pattern(raw_text, r"<Directory\s+\"/\">.*?Require\s+all\s+denied.*?</Directory>"),
        "<Directory /> có Require all denied",
        "Thêm 'Require all denied' vào thẻ <Directory />",
    )


def check_allowoverride_none(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        not _has_pattern(raw_text, r"^\s*AllowOverride\s+(?!None\b)\w+", flags=re.IGNORECASE | re.MULTILINE),
        "AllowOverride đã là None hoặc chưa mở rộng",
        "Đổi toàn bộ 'AllowOverride All' thành 'AllowOverride None'",
    )


def check_directory_root_options_none(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"<Directory\s+/?>.*?Options\s+None.*?</Directory>")
        or _has_pattern(raw_text, r"<Directory\s+\"/\">.*?Options\s+None.*?</Directory>"),
        "<Directory /> có Options None",
        "Thêm 'Options None' vào thẻ <Directory />",
    )


def check_dangerous_options_removed(raw_text: str) -> tuple[bool, str]:
    dangerous = _has_pattern(raw_text, r"^\s*Options\s+.*?(Indexes|Includes|ExecCGI|FollowSymLinks)", flags=re.IGNORECASE | re.MULTILINE)
    return _bool_result(
        not dangerous,
        "Không có Options nguy hiểm",
        "Xóa Indexes, Includes, ExecCGI, FollowSymLinks khỏi Options",
    )


def check_trace_enable_off(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*TraceEnable\s+off\b", flags=re.IGNORECASE | re.MULTILINE),
        "TraceEnable off",
        "Thêm dòng 'TraceEnable off'",
    )


def check_htaccess_block(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"<Files\s*\"?\.ht\*\"?>.*?Require\s+all\s+denied.*?</Files>"),
        "Đã chặn .ht*",
        "Phải có block .ht* (Require all denied)",
    )


def check_git_svn_block(raw_text: str) -> tuple[bool, str]:
    git_block = _has_pattern(raw_text, r"<DirectoryMatch\s+\".*\.git.*\">.*?Require\s+all\s+denied.*?</DirectoryMatch>")
    svn_block = _has_pattern(raw_text, r"<DirectoryMatch\s+\".*\.svn.*\">.*?Require\s+all\s+denied.*?</DirectoryMatch>")
    return _bool_result(
        git_block and svn_block,
        "Đã chặn .git và .svn",
        "Thêm block chặn .git và .svn",
    )


def check_listen_bound(raw_text: str) -> tuple[bool, str]:
    listen_80 = _has_pattern(raw_text, r"^\s*Listen\s+80\s*$", flags=re.IGNORECASE | re.MULTILINE)
    listen_any = _has_pattern(raw_text, r"^\s*Listen\s+0\.0\.0\.0", flags=re.IGNORECASE | re.MULTILINE)
    return _bool_result(
        not listen_80 and not listen_any,
        "Listen đã được ràng buộc theo IP",
        "Nên dùng Listen IP:Port thay vì chỉ Listen Port",
    )


def check_loglevel(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*LogLevel\s+(notice\s+core:info|info)\b", flags=re.IGNORECASE | re.MULTILINE),
        "LogLevel an toàn",
        "Nên đặt 'LogLevel notice core:info' hoặc 'info'",
    )


def check_errorlog(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*ErrorLog\s+.+", flags=re.IGNORECASE | re.MULTILINE),
        "ErrorLog đã bật",
        "Phải khai báo đường dẫn ErrorLog",
    )


def check_customlog(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*CustomLog\s+.+", flags=re.IGNORECASE | re.MULTILINE),
        "CustomLog đã bật",
        "Phải khai báo CustomLog",
    )


def check_ssl_protocol(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*SSLProtocol\s+.*-all.*(?=.*\+TLSv1\.2)(?=.*\+TLSv1\.3)", flags=re.IGNORECASE | re.MULTILINE),
        "SSLProtocol chỉ cho TLS 1.2/1.3",
        "Cần cấu hình SSLProtocol -all +TLSv1.2 +TLSv1.3",
    )


def check_ssl_honor_cipher_order(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*SSLHonorCipherOrder\s+On\b", flags=re.IGNORECASE | re.MULTILINE),
        "SSLHonorCipherOrder On",
        "Thêm 'SSLHonorCipherOrder On'",
    )


def check_server_tokens(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*ServerTokens\s+(Prod|ProductOnly)\b", flags=re.IGNORECASE | re.MULTILINE),
        "ServerTokens đã ẩn version",
        "Đặt 'ServerTokens Prod'",
    )


def check_server_signature(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*ServerSignature\s+Off\b", flags=re.IGNORECASE | re.MULTILINE),
        "ServerSignature Off",
        "Đặt 'ServerSignature Off'",
    )


def check_file_etag(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*FileETag\s+None\b", flags=re.IGNORECASE | re.MULTILINE)
        or not _has_pattern(raw_text, r"Inode", flags=re.IGNORECASE),
        "FileETag an toàn",
        "Đặt 'FileETag None' hoặc xóa 'Inode'",
    )


def check_timeout(raw_text: str) -> tuple[bool, str]:
    values = _directive_values(raw_text, "TimeOut") or _directive_values(raw_text, "Timeout")
    if not values:
        return False, "Timeout chưa được đặt"
    try:
        timeout_value = int(values[0])
    except ValueError:
        return False, f"TimeOut không hợp lệ: {values[0]}"
    return _bool_result(
        timeout_value <= 10,
        f"TimeOut {timeout_value}s",
        "Đặt 'TimeOut 10'",
    )


def check_keepalive_enabled(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        not _has_pattern(raw_text, r"^\s*KeepAlive\s+Off\b", flags=re.IGNORECASE | re.MULTILINE),
        "KeepAlive đã bật hoặc chưa bị tắt",
        "Đảm bảo 'KeepAlive On'",
    )


def check_max_keepalive_requests(raw_text: str) -> tuple[bool, str]:
    values = _directive_values(raw_text, "MaxKeepAliveRequests")
    if not values:
        return False, "MaxKeepAliveRequests chưa được đặt"
    try:
        value = int(values[0])
    except ValueError:
        return False, f"MaxKeepAliveRequests không hợp lệ: {values[0]}"
    return _bool_result(
        value >= 100,
        f"MaxKeepAliveRequests {value}",
        "Đặt 'MaxKeepAliveRequests 100'",
    )


def check_keepalive_timeout(raw_text: str) -> tuple[bool, str]:
    values = _directive_values(raw_text, "KeepAliveTimeout")
    if not values:
        return False, "KeepAliveTimeout chưa được đặt"
    try:
        value = int(values[0])
    except ValueError:
        return False, f"KeepAliveTimeout không hợp lệ: {values[0]}"
    return _bool_result(
        value <= 15,
        f"KeepAliveTimeout {value}",
        "Đặt 'KeepAliveTimeout 15'",
    )


def check_request_read_timeout(raw_text: str) -> tuple[bool, str]:
    return _bool_result(
        _has_pattern(raw_text, r"^\s*RequestReadTimeout\s+.+", flags=re.IGNORECASE | re.MULTILINE),
        "RequestReadTimeout đã bật",
        "Cấu hình RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500",
    )


def check_limit_request_line(raw_text: str) -> tuple[bool, str]:
    values = _directive_values(raw_text, "LimitRequestLine")
    if not values:
        return False, "LimitRequestLine chưa được đặt"
    try:
        value = int(values[0])
    except ValueError:
        return False, f"LimitRequestLine không hợp lệ: {values[0]}"
    return _bool_result(
        value <= 8190,
        f"LimitRequestLine {value}",
        "Đặt 'LimitRequestLine 512' (không vượt 8190)",
    )


def check_limit_request_fields(raw_text: str) -> tuple[bool, str]:
    values = _directive_values(raw_text, "LimitRequestFields")
    if not values:
        return False, "LimitRequestFields chưa được đặt"
    try:
        value = int(values[0])
    except ValueError:
        return False, f"LimitRequestFields không hợp lệ: {values[0]}"
    return _bool_result(
        value <= 100,
        f"LimitRequestFields {value}",
        "Đặt 'LimitRequestFields 100'",
    )


def check_limit_request_field_size(raw_text: str) -> tuple[bool, str]:
    values = _directive_values(raw_text, "LimitRequestFieldSize") or _directive_values(raw_text, "LimitRequestFieldsize")
    if not values:
        return False, "LimitRequestFieldSize chưa được đặt"
    try:
        value = int(values[0])
    except ValueError:
        return False, f"LimitRequestFieldSize không hợp lệ: {values[0]}"
    return _bool_result(
        value <= 8190,
        f"LimitRequestFieldSize {value}",
        "Đặt 'LimitRequestFieldSize 8190'",
    )


def check_limit_request_body(raw_text: str) -> tuple[bool, str]:
    values = _directive_values(raw_text, "LimitRequestBody")
    if not values:
        return False, "LimitRequestBody chưa được đặt"
    try:
        value = int(values[0])
    except ValueError:
        return False, f"LimitRequestBody không hợp lệ: {values[0]}"
    return _bool_result(
        value > 0,
        f"LimitRequestBody {value}",
        "Đặt 'LimitRequestBody 102400'",
    )


def check_limit_xml_request_body(raw_text: str) -> tuple[bool, str]:
    values = _directive_values(raw_text, "LimitXMLRequestBody")
    if not values:
        return False, "LimitXMLRequestBody chưa được đặt"
    try:
        value = int(values[0])
    except ValueError:
        return False, f"LimitXMLRequestBody không hợp lệ: {values[0]}"
    return _bool_result(
        value > 0,
        f"LimitXMLRequestBody {value}",
        "Đặt 'LimitXMLRequestBody 1000000'",
    )


APACHE_HTTP_RULE_SPECS: list[ApacheHttpRuleSpec] = [
    ApacheHttpRuleSpec(
        code="2.2",
        title="Đảm bảo Log Config Module được bật",
        severity="medium",
        search="LoadModule log_config_module",
        baseline="LoadModule log_config_module modules/mod_log_config.so",
        evaluator=check_log_config_module,
    ),
    ApacheHttpRuleSpec(
        code="2.3",
        title="Vô hiệu hóa WebDAV Modules",
        severity="medium",
        search="LoadModule dav_module|LoadModule dav_fs_module",
        baseline="#LoadModule dav_module modules/mod_dav.so\n#LoadModule dav_fs_module modules/mod_dav_fs.so",
        evaluator=lambda raw_text: _bool_result(
            not _has_pattern(raw_text, r"^\s*LoadModule\s+(dav_module|dav_fs_module)\b"),
            "WebDAV modules đã tắt",
            "Tắt mod_dav và mod_dav_fs",
        ),
    ),
    ApacheHttpRuleSpec(
        code="2.4",
        title="Vô hiệu hóa Status Module",
        severity="medium",
        search="LoadModule status_module",
        baseline="#LoadModule status_module modules/mod_status.so",
        evaluator=lambda raw_text: check_modules_disabled(raw_text, r"status_module", "mod_status"),
    ),
    ApacheHttpRuleSpec(
        code="2.5",
        title="Vô hiệu hóa Autoindex Module",
        severity="medium",
        search="LoadModule autoindex_module",
        baseline="#LoadModule autoindex_module modules/mod_autoindex.so",
        evaluator=lambda raw_text: check_modules_disabled(raw_text, r"autoindex_module", "mod_autoindex"),
    ),
    ApacheHttpRuleSpec(
        code="2.6",
        title="Vô hiệu hóa Proxy Modules",
        severity="high",
        search="LoadModule proxy_module",
        baseline="#LoadModule proxy_module modules/mod_proxy.so",
        evaluator=lambda raw_text: check_modules_disabled(raw_text, r"proxy_module", "mod_proxy"),
    ),
    ApacheHttpRuleSpec(
        code="2.7",
        title="Vô hiệu hóa User Directories Module",
        severity="medium",
        search="LoadModule userdir_module",
        baseline="#LoadModule userdir_module modules/mod_userdir.so",
        evaluator=lambda raw_text: check_modules_disabled(raw_text, r"userdir_module", "mod_userdir"),
    ),
    ApacheHttpRuleSpec(
        code="2.8",
        title="Vô hiệu hóa Info Module",
        severity="medium",
        search="LoadModule info_module",
        baseline="#LoadModule info_module modules/mod_info.so",
        evaluator=lambda raw_text: check_modules_disabled(raw_text, r"info_module", "mod_info"),
    ),
    ApacheHttpRuleSpec(
        code="2.9",
        title="Vô hiệu hóa Basic/Digest Auth Modules",
        severity="medium",
        search="LoadModule auth_basic_module|LoadModule auth_digest_module",
        baseline="#LoadModule auth_basic_module modules/mod_auth_basic.so\n#LoadModule auth_digest_module modules/mod_auth_digest.so",
        evaluator=lambda raw_text: _bool_result(
            not _has_pattern(raw_text, r"^\s*LoadModule\s+(auth_basic_module|auth_digest_module)\b"),
            "Auth Basic/Digest modules đã tắt",
            "Tắt mod_auth_basic / mod_auth_digest nếu không cần",
        ),
    ),
    ApacheHttpRuleSpec(
        code="3.1",
        title="Apache không được chạy bằng quyền root hoặc daemon",
        severity="critical",
        search="User|Group",
        baseline="User apache\nGroup apache",
        evaluator=check_user_not_privileged,
    ),
    ApacheHttpRuleSpec(
        code="3.2",
        title="Vô hiệu hóa Core Dump",
        severity="medium",
        search="CoreDumpDirectory",
        baseline="#CoreDumpDirectory /var/log/httpd",
        evaluator=check_core_dump_disabled,
    ),
    ApacheHttpRuleSpec(
        code="4.1",
        title="Từ chối truy cập toàn bộ hệ thống file OS",
        severity="critical",
        search="<Directory />|Require all denied",
        baseline="<Directory />\n    Require all denied\n</Directory>",
        evaluator=check_directory_root_denied,
    ),
    ApacheHttpRuleSpec(
        code="4.4",
        title="Vô hiệu hóa hoàn toàn AllowOverride",
        severity="high",
        search="AllowOverride",
        baseline="AllowOverride None",
        evaluator=check_allowoverride_none,
    ),
    ApacheHttpRuleSpec(
        code="5.1",
        title="Tắt toàn bộ Options cho thư mục gốc OS",
        severity="critical",
        search="<Directory />|Options None",
        baseline="<Directory />\n    Options None\n</Directory>",
        evaluator=check_directory_root_options_none,
    ),
    ApacheHttpRuleSpec(
        code="5.2",
        title="Xóa bỏ các Options nguy hiểm cho Web Root",
        severity="high",
        search="Options Indexes|Options Includes|Options ExecCGI|Options FollowSymLinks",
        baseline="# Không dùng Indexes, Includes, ExecCGI, FollowSymLinks",
        evaluator=check_dangerous_options_removed,
    ),
    ApacheHttpRuleSpec(
        code="5.8",
        title="Vô hiệu hóa phương thức HTTP TRACE",
        severity="high",
        search="TraceEnable",
        baseline="TraceEnable off",
        evaluator=check_trace_enable_off,
    ),
    ApacheHttpRuleSpec(
        code="5.10",
        title="Chặn truy cập các file ẩn cấu hình (.ht*)",
        severity="high",
        search="<Files|.ht*|Require all denied",
        baseline='<Files ".ht*">\n    Require all denied\n</Files>',
        evaluator=check_htaccess_block,
    ),
    ApacheHttpRuleSpec(
        code="5.11",
        title="Chặn truy cập thư mục .git, .svn",
        severity="high",
        search="DirectoryMatch|.git|.svn",
        baseline='<DirectoryMatch ".git">\n    Require all denied\n</DirectoryMatch>\n<DirectoryMatch ".svn">\n    Require all denied\n</DirectoryMatch>',
        evaluator=check_git_svn_block,
    ),
    ApacheHttpRuleSpec(
        code="5.15",
        title="Ràng buộc Listen vào IP cụ thể",
        severity="medium",
        search="Listen",
        baseline="Listen 10.0.0.1:80",
        evaluator=check_listen_bound,
    ),
    ApacheHttpRuleSpec(
        code="6.1",
        title="Cấu hình LogLevel an toàn",
        severity="medium",
        search="LogLevel",
        baseline="LogLevel notice core:info",
        evaluator=check_loglevel,
    ),
    ApacheHttpRuleSpec(
        code="6.2",
        title="Bật ErrorLog",
        severity="medium",
        search="ErrorLog",
        baseline='ErrorLog "logs/error_log"',
        evaluator=check_errorlog,
    ),
    ApacheHttpRuleSpec(
        code="6.4",
        title="Bật CustomLog (Access Log)",
        severity="medium",
        search="CustomLog",
        baseline='CustomLog "logs/access_log" combined',
        evaluator=check_customlog,
    ),
    ApacheHttpRuleSpec(
        code="7.6",
        title="Chỉ sử dụng TLS 1.2 và TLS 1.3",
        severity="critical",
        search="SSLProtocol",
        baseline="SSLProtocol -all +TLSv1.2 +TLSv1.3",
        evaluator=check_ssl_protocol,
    ),
    ApacheHttpRuleSpec(
        code="7.7",
        title="Bật tính năng ưu tiên Cipher của Server",
        severity="high",
        search="SSLHonorCipherOrder",
        baseline="SSLHonorCipherOrder On",
        evaluator=check_ssl_honor_cipher_order,
    ),
    ApacheHttpRuleSpec(
        code="8.1",
        title="Ẩn phiên bản Apache (ServerTokens)",
        severity="medium",
        search="ServerTokens",
        baseline="ServerTokens Prod",
        evaluator=check_server_tokens,
    ),
    ApacheHttpRuleSpec(
        code="8.2",
        title="Tắt chữ ký Server (ServerSignature)",
        severity="medium",
        search="ServerSignature",
        baseline="ServerSignature Off",
        evaluator=check_server_signature,
    ),
    ApacheHttpRuleSpec(
        code="8.4",
        title="Không sử dụng Inode trong ETag",
        severity="medium",
        search="FileETag|Inode",
        baseline="FileETag None",
        evaluator=check_file_etag,
    ),
    ApacheHttpRuleSpec(
        code="9.1",
        title="Giảm TimeOut xuống 10 giây hoặc thấp hơn",
        severity="medium",
        search="TimeOut|Timeout",
        baseline="TimeOut 10",
        evaluator=check_timeout,
    ),
    ApacheHttpRuleSpec(
        code="9.2",
        title="Đảm bảo KeepAlive được bật",
        severity="medium",
        search="KeepAlive",
        baseline="KeepAlive On",
        evaluator=check_keepalive_enabled,
    ),
    ApacheHttpRuleSpec(
        code="9.3",
        title="MaxKeepAliveRequests phải từ 100 trở lên",
        severity="medium",
        search="MaxKeepAliveRequests",
        baseline="MaxKeepAliveRequests 100",
        evaluator=check_max_keepalive_requests,
    ),
    ApacheHttpRuleSpec(
        code="9.4",
        title="KeepAliveTimeout phải từ 15 giây trở xuống",
        severity="medium",
        search="KeepAliveTimeout",
        baseline="KeepAliveTimeout 15",
        evaluator=check_keepalive_timeout,
    ),
    ApacheHttpRuleSpec(
        code="9.5",
        title="Sử dụng mod_reqtimeout (RequestReadTimeout)",
        severity="medium",
        search="RequestReadTimeout",
        baseline="RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500",
        evaluator=check_request_read_timeout,
    ),
    ApacheHttpRuleSpec(
        code="10.1",
        title="Giới hạn độ dài URL (LimitRequestLine)",
        severity="medium",
        search="LimitRequestLine",
        baseline="LimitRequestLine 8190",
        evaluator=check_limit_request_line,
    ),
    ApacheHttpRuleSpec(
        code="10.2",
        title="Giới hạn số lượng Header (LimitRequestFields)",
        severity="medium",
        search="LimitRequestFields",
        baseline="LimitRequestFields 100",
        evaluator=check_limit_request_fields,
    ),
    ApacheHttpRuleSpec(
        code="10.3",
        title="Giới hạn kích thước Header (LimitRequestFieldSize)",
        severity="medium",
        search="LimitRequestFieldSize|LimitRequestFieldsize",
        baseline="LimitRequestFieldSize 8190",
        evaluator=check_limit_request_field_size,
    ),
    ApacheHttpRuleSpec(
        code="10.4",
        title="Giới hạn Payload Body (LimitRequestBody)",
        severity="high",
        search="LimitRequestBody",
        baseline="LimitRequestBody 102400",
        evaluator=check_limit_request_body,
    ),
    ApacheHttpRuleSpec(
        code="10.5",
        title="Giới hạn XML Payload (LimitXMLRequestBody)",
        severity="high",
        search="LimitXMLRequestBody",
        baseline="LimitXMLRequestBody 1000000",
        evaluator=check_limit_xml_request_body,
    ),
]


def build_apache_http_config_checks(prefix: str) -> list[RuleCheck]:
    checks: list[RuleCheck] = []
    for spec in APACHE_HTTP_RULE_SPECS:
        checks.append(
            RuleCheck(
                code=spec.code,
                title=spec.title,
                severity=spec.severity,
                weight=1,
                config_file_key="apache",
                evaluator=spec.evaluator,
            )
        )
    return checks
