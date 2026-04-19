from __future__ import annotations

from ...models import ModuleDefinition
from .http_scanner import APACHE_HTTP_RULE_SPECS, build_apache_http_config_checks


APACHE_HTTP_EXPLANATIONS: dict[str, str] = {
    "2.2": "Bật log_config_module để Apache có thể ghi log theo đúng cấu trúc chuẩn. Nếu thiếu module này, hệ thống mất khả năng ghi nhận truy vết truy cập và lỗi một cách đầy đủ, làm giảm khả năng điều tra sự cố.",
    "2.3": "mod_dav và mod_dav_fs hỗ trợ WebDAV, nhưng nếu không dùng thì nên tắt để thu hẹp bề mặt tấn công. WebDAV mở thêm các thao tác upload và chỉnh sửa tài nguyên mà ứng dụng không cần.",
    "2.4": "mod_status có thể lộ trạng thái hoạt động, tiến trình và thông tin nội bộ của Apache. Nên tắt nếu không thật sự phục vụ vận hành, vì nó làm tăng rủi ro lộ thông tin hệ thống.",
    "2.5": "mod_autoindex cho phép liệt kê nội dung thư mục khi không có index file. Điều này có thể làm lộ file cấu hình, file backup hoặc mã nguồn, nên cần vô hiệu hóa.",
    "2.6": "mod_proxy và các module proxy liên quan chỉ nên bật khi máy chủ thực sự đóng vai trò reverse proxy. Nếu không cần, hãy tắt để tránh bị lạm dụng thành điểm trung chuyển hoặc SSRF proxy.",
    "2.7": "mod_userdir cho phép phục vụ nội dung từ thư mục người dùng. Cơ chế này dễ làm phát sinh nhầm lẫn quyền truy cập và rò rỉ nội dung cá nhân, nên thường phải tắt.",
    "2.8": "mod_info có thể tiết lộ cấu hình nội bộ, đường dẫn module và chi tiết build. Đây là thông tin hữu ích cho kẻ tấn công nên cần loại bỏ khi không dùng.",
    "2.9": "Các module auth_basic và auth_digest chỉ cần khi hệ thống dùng xác thực kiểu cũ. Nếu ứng dụng đã dùng SSO hoặc cơ chế xác thực khác thì nên tắt để giảm lớp xử lý thừa và tránh cấu hình yếu.",
    "3.1": "Apache không nên chạy bằng root hoặc daemon vì khi bị khai thác, kẻ tấn công sẽ có toàn quyền cao nhất trên máy. Chạy bằng tài khoản riêng biệt giúp giới hạn thiệt hại khi có lỗi hoặc bị xâm nhập.",
    "3.2": "Core dump có thể chứa dữ liệu nhạy cảm trong bộ nhớ như session, token hoặc chuỗi cấu hình. Không bật CoreDumpDirectory nếu không phục vụ debug nội bộ có kiểm soát.",
    "4.1": "Thư mục gốc hệ thống phải bị từ chối mặc định để ngăn truy cập ngoài ý muốn vào file của OS. Nếu thiếu chặn này, lỗi cấu hình có thể dẫn tới đọc file trái phép.",
    "4.4": "AllowOverride quá rộng cho phép .htaccess ghi đè nhiều hành vi an ninh ở cấp thư mục. Chuyển sang None giúp cấu hình tập trung, dễ kiểm soát và giảm nguy cơ bị lạm dụng.",
    "5.1": "Options None ở root giúp tắt các hành vi mặc định có thể gây lộ file hoặc thực thi ngoài ý muốn. Đây là lớp hạn chế cần có để thư mục gốc không bị cấu hình mở quá mức.",
    "5.2": "Indexes, Includes, ExecCGI và FollowSymLinks đều có thể mở thêm khả năng lộ nội dung hoặc thực thi. Chỉ giữ những option thật sự cần thiết để giảm bề mặt tấn công.",
    "5.8": "TRACE method có thể bị lợi dụng cho XST và các kỹ thuật phản chiếu request. Tắt TraceEnable là cách đơn giản để chặn nhóm tấn công này.",
    "5.10": "Các file .ht* thường chứa chính sách truy cập và xác thực nội bộ. Nếu lộ ra ngoài, attacker có thể đọc cách hệ thống kiểm soát quyền và khai thác tiếp.",
    "5.11": ".git và .svn chứa lịch sử mã nguồn, cấu trúc thư mục và đôi khi cả bí mật đã vô tình commit. Chặn truy cập là bắt buộc nếu các thư mục này còn tồn tại trong web root.",
    "5.15": "Ràng buộc Listen vào IP cụ thể giúp Apache chỉ nghe trên interface cần thiết. Nếu chỉ Listen 80 hoặc 0.0.0.0 thì dịch vụ sẽ phơi ra toàn bộ mạng không cần thiết.",
    "6.1": "LogLevel nên ở mức đủ để điều tra nhưng không quá chi tiết. Quá thấp có thể làm lộ cấu trúc nội bộ; quá cao lại gây khó truy vết và tốn tài nguyên.",
    "6.2": "ErrorLog là nguồn chính để theo dõi lỗi cấu hình, lỗi truy cập và dấu hiệu khai thác. Không khai báo rõ ràng sẽ làm mất khả năng quan sát khi có sự cố.",
    "6.4": "CustomLog giữ lịch sử truy cập để phân tích hành vi, điều tra sự cố và audit. Nếu thiếu access log, bạn mất một lớp kiểm tra rất quan trọng.",
    "7.6": "Chỉ cho phép TLS 1.2 và TLS 1.3 để loại bỏ giao thức cũ yếu như TLS 1.0/1.1. Điều này giảm nguy cơ downgrade attack và các lỗ hổng mật mã đã lỗi thời.",
    "7.7": "SSLHonorCipherOrder On buộc server quyết định thứ tự cipher mạnh, không phụ thuộc client. Cách này giúp tránh bị chọn cipher yếu nếu client ưu tiên thuật toán cũ.",
    "8.1": "ServerTokens quá chi tiết sẽ tiết lộ phiên bản Apache và nền tảng chạy phía sau. Ẩn version giúp giảm thông tin mà attacker có thể dùng để tra cứu khai thác.",
    "8.2": "ServerSignature Off ngăn Apache in thêm phiên bản trên trang lỗi và output mặc định. Đây là một biện pháp giảm rò rỉ thông tin rất đơn giản nhưng hiệu quả.",
    "8.4": "FileETag không nên chứa Inode vì inode có thể làm lộ đặc điểm nội bộ hệ thống file và không mang lại lợi ích an ninh. Dùng None hoặc MTime Size là an toàn hơn.",
    "9.1": "TimeOut quá cao khiến kết nối treo chiếm tài nguyên lâu hơn và làm tăng rủi ro DoS kiểu slow request. Giới hạn thấp hơn giúp máy chủ hồi phục nhanh hơn khi bị giữ kết nối.",
    "9.2": "KeepAlive giúp tái sử dụng kết nối, nhưng nếu bị tắt hoàn toàn thì hiệu năng giảm và người quản trị dễ cấu hình lệch. Quy tắc này kiểm tra để tránh trạng thái bất thường không mong muốn.",
    "9.3": "MaxKeepAliveRequests cần đủ lớn để cân bằng hiệu năng, nhưng không nên bỏ mặc mặc định nếu policy yêu cầu. Giá trị hợp lý giúp tránh mở kết nối lâu nhưng vẫn phục vụ tốt client.",
    "9.4": "KeepAliveTimeout quá cao sẽ giữ socket không cần thiết và tạo điều kiện cho DoS. Giới hạn ngắn hơn giúp tài nguyên được giải phóng sớm.",
    "9.5": "RequestReadTimeout kiểm soát tốc độ gửi header/body, chặn kiểu slowloris và request body chậm. Thiếu cấu hình này, attacker có thể chiếm worker bằng các request kéo dài.",
    "10.1": "LimitRequestLine giới hạn độ dài URL và request line để ngăn các request bất thường rất dài. Giới hạn này giúp giảm nguy cơ tràn bộ nhớ và tấn công tài nguyên.",
    "10.2": "LimitRequestFields giới hạn số header trong một request để tránh đầu vào phình to bất thường. Nếu không có giới hạn, attacker có thể dùng request cực lớn để gây áp lực xử lý.",
    "10.3": "LimitRequestFieldSize giới hạn kích thước từng header. Đây là lớp bảo vệ cần có để ngăn header quá dài làm tốn bộ nhớ và gây lỗi xử lý.",
    "10.4": "LimitRequestBody kiểm soát kích thước payload nhận vào. Nếu để quá lớn hoặc không đặt phù hợp, hệ thống có thể bị tiêu hao tài nguyên bởi request upload khổng lồ.",
    "10.5": "LimitXMLRequestBody hữu ích khi dịch vụ xử lý XML hoặc SOAP. Giới hạn này ngăn payload XML quá lớn gây DoS hoặc làm ứng dụng xử lý chậm bất thường.",
}


def build_apache_http_config_metadata() -> dict[str, dict[str, str]]:
    metadata: dict[str, dict[str, str]] = {}
    for spec in APACHE_HTTP_RULE_SPECS:
        metadata[spec.code] = {
            "search": spec.search,
            "baseline": spec.baseline,
            "explanation": APACHE_HTTP_EXPLANATIONS.get(spec.code, ""),
        }
    return metadata


APACHE_HTTP_CHECK_METADATA = build_apache_http_config_metadata()


def windows_apache_http_config_paths() -> list[str]:
    return [
        r"C:\xampp\apache\conf\httpd.conf",
        r"C:\Apache24\conf\httpd.conf",
        r"C:\Program Files\Apache Group\Apache2\conf\httpd.conf",
    ]


def linux_apache_http_config_paths() -> list[str]:
    return [
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
        "/etc/apache2/conf-enabled/security.conf",
    ]


def macos_apache_http_config_paths() -> list[str]:
    return [
        "/usr/local/etc/apache2/2.4/httpd.conf",
        "/etc/apache2/httpd.conf",
    ]


def build_apache_http_config_module(
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
        checks=build_apache_http_config_checks(prefix),
        check_metadata=APACHE_HTTP_CHECK_METADATA,
    )
