from __future__ import annotations

from ..common import make_directive_check
from ...models import ModuleDefinition, RuleCheck


SSH_RULE_EXPLANATIONS: dict[str, str] = {
    "001": "PermitRootLogin no ngăn đăng nhập SSH trực tiếp bằng tài khoản root. Nếu root bị lộ mật khẩu hoặc bị brute-force, attacker sẽ có ngay quyền cao nhất trên máy.",
    "002": "PermitEmptyPasswords no chặn tài khoản không có mật khẩu. Một cấu hình cho phép mật khẩu rỗng sẽ làm việc truy cập trái phép trở nên quá dễ dàng.",
    "003": "MaxAuthTries 4 giới hạn số lần thử đăng nhập trước khi ngắt phiên. Giá trị cao hơn làm tăng hiệu quả của brute-force và password spraying.",
    "004": "HostbasedAuthentication no tắt cơ chế xác thực dựa trên host tin cậy. Cơ chế này khó kiểm soát và dễ bị lạm dụng nếu hệ thống tin cậy bị compromise.",
    "005": "PermitUserEnvironment no ngăn người dùng chèn biến môi trường từ file cấu hình cá nhân. Nếu bật, attacker có thể điều hướng hành vi phiên SSH theo cách ngoài ý muốn.",
    "006": "UsePAM yes cho phép áp dụng chính sách xác thực và khóa tài khoản tập trung. Tắt PAM làm mất một lớp kiểm soát quan trọng của hệ thống.",
    "007": "ClientAliveInterval 15 giúp phát hiện kết nối treo và thu hồi tài nguyên sớm hơn. Nếu quá lớn hoặc không đặt đúng, phiên treo có thể giữ socket và worker không cần thiết.",
    "008": "ClientAliveCountMax 3 giới hạn số lần kiểm tra liveness trước khi ngắt kết nối. Thiết lập hợp lý giúp chống treo phiên lâu và giảm rủi ro cạn tài nguyên.",
    "009": "LoginGraceTime 60 giới hạn thời gian chờ xác thực ban đầu. Nếu để quá dài, attacker có thêm thời gian cho brute-force hoặc giữ kết nối mở để gây áp lực tài nguyên.",
    "010": "DisableForwarding yes tắt port forwarding, X11 forwarding và agent forwarding. Đây là nhóm tính năng có thể bị lợi dụng để pivot hoặc mở đường sang tài nguyên nội bộ.",
    "011": "Banner /etc/issue.net hiển thị thông báo pháp lý và cảnh báo truy cập hợp lệ. Dùng banner đúng chuẩn giúp đáp ứng yêu cầu audit và cảnh báo người dùng không được phép truy cập.",
}


def linux_ssh_paths() -> list[str]:
    return ["/etc/ssh/sshd_config"]


def windows_ssh_paths() -> list[str]:
    return [r"C:\ProgramData\ssh\sshd_config"]


def macos_ssh_paths() -> list[str]:
    return ["/etc/ssh/sshd_config"]


def build_ssh_checks(prefix: str) -> list[RuleCheck]:
    key = "ssh"
    return [
        make_directive_check(f"{prefix}-001", "Disable direct root login", "critical", key, "PermitRootLogin", "no", SSH_RULE_EXPLANATIONS["001"]),
        make_directive_check(f"{prefix}-002", "Disallow empty passwords", "critical", key, "PermitEmptyPasswords", "no", SSH_RULE_EXPLANATIONS["002"]),
        make_directive_check(f"{prefix}-003", "Limit auth retries", "high", key, "MaxAuthTries", "4", SSH_RULE_EXPLANATIONS["003"]),
        make_directive_check(f"{prefix}-004", "Disable host-based auth", "high", key, "HostbasedAuthentication", "no", SSH_RULE_EXPLANATIONS["004"]),
        make_directive_check(f"{prefix}-005", "Disable user environment overrides", "high", key, "PermitUserEnvironment", "no", SSH_RULE_EXPLANATIONS["005"]),
        make_directive_check(f"{prefix}-006", "Enable PAM", "medium", key, "UsePAM", "yes", SSH_RULE_EXPLANATIONS["006"]),
        make_directive_check(f"{prefix}-007", "Set keep-alive interval", "medium", key, "ClientAliveInterval", "15", SSH_RULE_EXPLANATIONS["007"]),
        make_directive_check(f"{prefix}-008", "Set keep-alive max count", "medium", key, "ClientAliveCountMax", "3", SSH_RULE_EXPLANATIONS["008"]),
        make_directive_check(f"{prefix}-009", "Set login grace timeout", "medium", key, "LoginGraceTime", "60", SSH_RULE_EXPLANATIONS["009"]),
        make_directive_check(f"{prefix}-010", "Disable forwarding", "high", key, "DisableForwarding", "yes", SSH_RULE_EXPLANATIONS["010"]),
        make_directive_check(f"{prefix}-011", "Set legal banner", "low", key, "Banner", "/etc/issue.net", SSH_RULE_EXPLANATIONS["011"]),
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
