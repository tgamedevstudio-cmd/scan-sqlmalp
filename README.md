SQL INJECTION SCANNER - CÔNG CỤ QUÉT LỖ HỔNG BẢO MẬT
=====================================================

TỔNG QUAN
---------
SQL Injection Scanner là công cụ kiểm tra lỗ hổng bảo mật ứng dụng web 
được viết bằng ngôn ngữ C++ trên nền tảng Windows Visual Studio 2022. 
Công cụ hoạt động ở tầng ứng dụng, mô phỏng các kỹ thuật tấn công SQL 
Injection để đánh giá mức độ an toàn của hệ thống mục tiêu.

MỤC ĐÍCH SỬ DỤNG
----------------
1. Đánh giá lỗ hổng bảo mật trên hệ thống được ủy quyền
2. Kiểm tra an toàn ứng dụng web trong quá trình phát triển
3. Hỗ trợ kiểm thử xâm nhập (Penetration Testing)
4. Đào tạo và nghiên cứu về an ninh mạng

CẢNH BÁO PHÁP LÝ
----------------
Công cụ này chỉ được sử dụng trên các hệ thống mà bạn đã được ủy quyền 
bằng văn bản. Việc sử dụng trái phép để tấn công hệ thống của người khác 
là vi phạm pháp luật. Tác giả không chịu trách nhiệm về bất kỳ hành vi 
sử dụng sai mục đích nào.

THÔNG TIN KỸ THUẬT
------------------
Ngôn ngữ lập trình: C++ 17
Môi trường phát triển: Visual Studio 2022
Hệ điều hành: Windows 10/11 (x64)
Thư viện sử dụng: WinSock2, STL (chuẩn C++)
Kết nối: TCP/IP qua HTTP (port 80)

KIẾN TRÚC HỆ THỐNG
------------------
1. Module giao tiếp mạng
   - Tạo socket TCP/IP
   - Xây dựng HTTP request
   - Xử lý response

2. Module phát hiện lỗ hổng
   - Boolean-based detection
   - Error-based detection
   - Time-based detection
   - Union-based detection

3. Module xử lý payload
   - URL encoding
   - Chèn payload vào request
   - Quản lý danh sách payload

4. Module ghi nhật ký
   - Ghi log ra file
   - Hiển thị màu sắc console
   - Báo cáo kết quả

CÁC KỸ THUẬT TẤN CÔNG ĐƯỢC MÔ PHỎNG
------------------------------------
1. Boolean-based Blind SQL Injection
   - Kỹ thuật: So sánh response giữa true và false
   - Payload mẫu: ' AND '1'='1  và  ' AND '1'='2
   - Cơ chế: Dựa vào sự khác biệt nội dung trang

2. Error-based SQL Injection
   - Kỹ thuật: Khai thác thông báo lỗi SQL
   - Payload mẫu: ' AND extractvalue(1,concat(0x7e,database()))-- -
   - Cơ chế: Ép cơ sở dữ liệu sinh ra lỗi

3. Time-based Blind SQL Injection
   - Kỹ thuật: Đo thời gian phản hồi
   - Payload mẫu: ' AND SLEEP(5)-- -
   - Cơ chế: Sử dụng hàm gây trễ

4. Union-based SQL Injection
   - Kỹ thuật: Kết hợp kết quả truy vấn
   - Payload mẫu: ' UNION SELECT NULL-- -
   - Cơ chế: Ghép thêm kết quả truy vấn

CÀI ĐẶT VÀ TRIỂN KHAI
---------------------
Bước 1: Cài đặt Visual Studio 2022
   - Tải từ trang chủ Microsoft
   - Chọn workload "Desktop development with C++"

Bước 2: Tạo project mới
   - File -> New -> Project
   - Chọn "Console App (C++)"
   - Đặt tên: SQLInjectionScanner

Bước 3: Cấu hình project
   - Project -> Properties
   - C++ Language Standard: ISO C++17 Standard
   - Linker -> Input -> Additional Dependencies
   - Thêm: ws2_32.lib

Bước 4: Biên dịch
   - Build -> Build Solution
   - File thực thi nằm trong thư mục Debug hoặc Release

HƯỚNG DẪN SỬ DỤNG CHI TIẾT
---------------------------
1. Cú pháp cơ bản:
   SQLInjectionScanner.exe -u <URL> [tùy chọn]

2. Tham số dòng lệnh:
   -u      : URL mục tiêu (bắt buộc)
   --data  : Dữ liệu POST, dùng [INJECT] làm điểm chèn payload

3. Ví dụ kiểm tra GET parameter:
   SQLInjectionScanner.exe -u "http://192.168.1.100/product.php?id=1"

4. Ví dụ kiểm tra POST form:
   SQLInjectionScanner.exe -u "http://192.168.1.100/login.php" --data="user=admin&pass=[INJECT]"

5. Ví dụ kiểm tra với port khác:
   SQLInjectionScanner.exe -u "http://192.168.1.100:8080/search.php?q=test"

QUY TRÌNH QUÉT LỖ HỔNG
----------------------
1. Thu thập baseline
   - Gửi request không có payload
   - Ghi nhận thời gian và kích thước response

2. Duyệt danh sách payload
   - Lần lượt gửi từng payload
   - So sánh với baseline

3. Phân tích kết quả
   - Phát hiện lỗi SQL trong response
   - So sánh sự khác biệt nội dung
   - Đo thời gian phản hồi

4. Tổng hợp báo cáo
   - Liệt kê các payload thành công
   - Đề xuất biện pháp khắc phục

DANH SÁCH PAYLOAD CHI TIẾT
--------------------------
A. Boolean-based (04 payload)
   1. ' AND '1'='1
   2. ' AND '1'='2
   3. ' OR '1'='1
   4. ' OR '1'='2

B. Error-based (04 payload)
   1. ' AND extractvalue(1,concat(0x7e,database()))-- -
   2. ' AND updatexml(1,concat(0x7e,database()),1)-- -
   3. ' AND 1=cast((SELECT version()) as int)-- -
   4. ' AND 1=convert(int,@@version)-- -

C. Time-based (03 payload)
   1. ' AND SLEEP(5)-- -
   2. ' AND pg_sleep(5)-- -
   3. '; WAITFOR DELAY '00:00:05'-- -

D. Union-based (06 payload)
   1. ' UNION SELECT NULL-- -
   2. ' UNION SELECT NULL,NULL-- -
   3. ' UNION SELECT NULL,NULL,NULL-- -
   4. ' UNION SELECT NULL,NULL,NULL,NULL-- -
   5. ' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -
   6. ' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -

Tổng số payload: 17

ĐỌC VÀ PHÂN TÍCH KẾT QUẢ
-------------------------
1. Mã màu báo cáo:
   [*] - Thông tin (màu xanh dương)
   [+] - An toàn / Thành công (màu xanh lá)
   [!] - Cảnh báo (màu vàng)
   [-] - Lỗi (màu đỏ)
   [!!!] - Lỗ hổng (màu đỏ đậm)

2. Các trường hợp phát hiện lỗ hổng:
   - "Response khác biệt": Boolean-based SQLi
   - "Phát hiện lỗi SQL": Error-based SQLi
   - "Delay: X ms": Time-based SQLi
   - "Trích xuất: data": Union-based SQLi

3. File log: sql_scan_log.txt
   - Lưu toàn bộ quá trình quét
   - Có timestamp cho mỗi lần chạy

XỬ LÝ SỰ CỐ
-----------
1. Lỗi "Cannot connect to target"
   Nguyên nhân:
   - Sai địa chỉ URL
   - Mục tiêu không hoạt động
   - Firewall chặn kết nối
   
   Khắc phục:
   - Kiểm tra lại URL
   - Dùng lệnh ping để kiểm tra
   - Tắt firewall tạm thời

2. Lỗi "Winsock initialization failed"
   Nguyên nhân:
   - Thiếu thư viện ws2_32.dll
   - Quyền thực thi không đủ
   
   Khắc phục:
   - Chạy với quyền Administrator
   - Kiểm tra file hệ thống

3. Lỗi "Cannot resolve host"
   Nguyên nhân:
   - Tên miền không tồn tại
   - DNS không hoạt động
   
   Khắc phục:
   - Dùng địa chỉ IP thay vì tên miền
   - Kiểm tra cấu hình DNS

4. Timeout khi nhận response
   Nguyên nhân:
   - Mạng chậm
   - Mục tiêu quá tải
   
   Khắc phục:
   - Tăng giá trị timeout trong code
   - Giảm số lượng payload

BIỆN PHÁP PHÒNG CHỐNG SQL INJECTION
-----------------------------------
1. Tầng ứng dụng
   - Sử dụng Parameterized Query
   - Dùng Prepared Statement
   - Kiểm tra đầu vào (Input Validation)

2. Tầng cơ sở dữ liệu
   - Phân quyền tối thiểu
   - Không dùng tài khoản admin cho ứng dụng
   - Ẩn thông báo lỗi

3. Tầng mạng
   - Triển khai WAF (Web Application Firewall)
   - Giám sát traffic bất thường
   - Ghi log truy cập

4. Quy trình phát triển
   - Kiểm tra bảo mật định kỳ
   - Đào tạo lập trình viên
   - Code review trước khi triển khai

GIỚI HẠN CỦA CÔNG CỤ
--------------------
1. Chưa hỗ trợ HTTPS (chỉ HTTP)
2. Chưa xử lý cookie và session
3. Chưa hỗ trợ xác thực (authentication)
4. Chưa có cơ chế tránh IDS/IPS
5. Tốc độ quét chậm do delay giữa các request
6. Chưa phát hiện second-order SQL injection

PHÁT TRIỂN VÀ MỞ RỘNG
---------------------
1. Thêm payload mới:
   - Thêm vào mảng payloads trong hàm initPayloads()
   - Định dạng: Payload("tên", "payload", "kỹ thuật")

2. Thêm kỹ thuật phát hiện mới:
   - Tạo hàm phát hiện riêng
   - Thêm vào vòng lặp kiểm tra

3. Hỗ trợ HTTPS:
   - Sử dụng OpenSSL hoặc Windows SChannel
   - Cần thêm thư viện bên thứ ba

4. Thêm xử lý cookie:
   - Lưu cookie từ response đầu tiên
   - Gửi lại trong các request sau

LỊCH SỬ PHIÊN BẢN
-----------------
Phiên bản 1.0 (Tháng 1, 2025)
   - Phát hành lần đầu
   - Hỗ trợ 4 kỹ thuật SQL injection cơ bản
   - Hỗ trợ GET và POST method
   - Ghi log ra file

TÀI LIỆU THAM KHẢO
------------------
1. OWASP SQL Injection Prevention Cheat Sheet
2. CWE-89: Improper Neutralization of Special Elements
3. MITRE ATT&CK Technique T1190
4. Common Vulnerability Scoring System v3.1

LƯU Ý QUAN TRỌNG
----------------
Công cụ này được phát triển cho mục đích kiểm tra bảo mật và nghiên cứu.
Người dùng phải tuân thủ đầy đủ các quy định pháp luật về an ninh mạng
tại quốc gia sử dụng. Tác giả không chịu trách nhiệm cho bất kỳ hành vi
vi phạm nào phát sinh từ việc sử dụng công cụ.
