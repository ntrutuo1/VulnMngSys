import abc
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

@dataclass(frozen=True)
class Rule:
    """Domain model đại diện cho 1 cấu hình kiểm tra."""
    id: str
    title: str
    service: str  # Tên service được map (ví dụ: 'IIS', 'SQL Server')
    check_type: str
    expected: Any
    description: str = ""
    remediation: str = ""
    # Chứa thêm các field tuỳ biến của JSON (powershell_check, registry_path, vv.)
    raw_spec: Dict[str, Any] = None


@dataclass(frozen=True)
class RuleComparisonResult:
    """Kết quả kiểm tra 1 Rule."""
    passed: bool
    verdict: str  # 'PASS', 'FAIL', 'MANUAL', 'ERROR'
    actual_value: Any
    expected_value: Any
    error_message: Optional[str] = None


class SystemCollector(abc.ABC):
    """Protocol thu thập dữ liệu từ OS (Registry, WMI, Secedit...)."""
    
    @abc.abstractmethod
    def get_registry_value(self, hive: str, key: str, value_name: str) -> Tuple[Any, str]:
        """Trả về (giá trị thực tế, kiểu dữ liệu text)"""
        pass

    @abc.abstractmethod
    def run_powershell(self, command: str, timeout: int = 60) -> str:
        """Chạy script PowerShell và trả về stdout/stderr gộp lại."""
        pass
        
    @abc.abstractmethod
    def get_secedit_policy(self) -> Dict[str, str]:
        """Lấy tất cả Security Policy hiện tại."""
        pass

    @abc.abstractmethod
    def get_user_rights(self) -> Dict[str, List[str]]:
        """Lấy User Rights Assignment."""
        pass
        
    @abc.abstractmethod
    def get_audit_policy(self) -> Dict[str, str]:
        """Lấy thông tin Audit Policy."""
        pass

class RuleChecker(abc.ABC):
    """Protocol đánh giá 1 Rule."""
    
    @abc.abstractmethod
    def can_handle(self, rule: Rule) -> bool:
        """Checker này có hỗ trợ rule này không?"""
        pass
        
    @abc.abstractmethod
    def check(self, rule: Rule, collector: SystemCollector) -> RuleComparisonResult:
        """Tiến hành kiểm tra."""
        pass
