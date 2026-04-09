#include "OnvifDiscovery.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <pugixml.hpp>
#include <cstring>
#include <cstdio>
#include <string>
#include <sstream>

// WS-Discovery Probe 메시지
static const char* WS_DISCOVERY_PROBE =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
    " xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
    " xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\">"
    "<soap:Header>"
    "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
    "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
    "<wsa:MessageID>urn:uuid:12345678-1234-1234-1234-123456789abc</wsa:MessageID>"
    "</soap:Header>"
    "<soap:Body>"
    "<wsd:Probe>"
    "<wsd:Types>wsdp:Device</wsd:Types>"
    "</wsd:Probe>"
    "</soap:Body>"
    "</soap:Envelope>";

#define WS_DISCOVERY_ADDR "239.255.255.250"
#define WS_DISCOVERY_PORT 3702
#define RECV_BUF_SIZE     65536

// 응답 XML에서 XAddrs (서비스 URL) 추출
static std::string extract_xaddrs(const std::string& xml) {
    pugi::xml_document doc;
    if (!doc.load_string(xml.c_str())) return "";

    // XAddrs는 여러 네임스페이스 경로에 있을 수 있음
    // 재귀적으로 "XAddrs" 이름의 노드를 찾음
    struct XAddrsFinder : pugi::xml_tree_walker {
        std::string result;
        bool for_each(pugi::xml_node& node) override {
            std::string name = node.name();
            if (name.find("XAddrs") != std::string::npos) {
                result = node.text().get();
                return false;  // 찾으면 중단
            }
            return true;
        }
    };

    XAddrsFinder finder;
    doc.traverse(finder);

    // XAddrs에 공백으로 구분된 여러 URL이 있을 수 있음 → 첫 번째만
    std::string addrs = finder.result;
    auto space = addrs.find(' ');
    if (space != std::string::npos) {
        addrs = addrs.substr(0, space);
    }

    return addrs;
}

// XAddrs URL에서 IP 추출
static std::string extract_ip_from_url(const std::string& url) {
    // "http://192.168.0.64:80/onvif/device_service" → "192.168.0.64"
    auto start = url.find("://");
    if (start == std::string::npos) return "";
    start += 3;
    auto end = url.find_first_of(":/", start);
    if (end == std::string::npos) return url.substr(start);
    return url.substr(start, end - start);
}

bool onvif_discover(int timeout_ms, std::vector<OnvifDevice>& devices) {
    devices.clear();

    if (timeout_ms <= 0) timeout_ms = 3000;

#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return false;
#else
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return false;
#endif

    // SO_REUSEADDR
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    // 수신 타임아웃 설정
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    // 멀티캐스트 대상 주소
    struct sockaddr_in dest = {};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(WS_DISCOVERY_PORT);
    inet_pton(AF_INET, WS_DISCOVERY_ADDR, &dest.sin_addr);

    // Probe 전송
    int sent = sendto(sock, WS_DISCOVERY_PROBE, static_cast<int>(strlen(WS_DISCOVERY_PROBE)),
                      0, reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
    if (sent <= 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return false;
    }

    // 응답 수신 (타임아웃까지 반복)
    char buf[RECV_BUF_SIZE];
    struct sockaddr_in from = {};
    while (true) {
#ifdef _WIN32
        int fromLen = sizeof(from);
#else
        socklen_t fromLen = sizeof(from);
#endif
        int recvLen = recvfrom(sock, buf, RECV_BUF_SIZE - 1, 0,
                               reinterpret_cast<struct sockaddr*>(&from), &fromLen);
        if (recvLen <= 0) break;  // 타임아웃 또는 에러

        buf[recvLen] = '\0';

        std::string xml(buf, recvLen);
        std::string xaddrs = extract_xaddrs(xml);

        if (!xaddrs.empty()) {
            OnvifDevice dev;
            dev.service_url = xaddrs;
            dev.ip = extract_ip_from_url(xaddrs);

            // 중복 IP 제거
            bool dup = false;
            for (const auto& d : devices) {
                if (d.ip == dev.ip) { dup = true; break; }
            }
            if (!dup) {
                devices.push_back(dev);
            }
        }
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    return true;
}

// ============================================================
// #11 ONVIF 상세 정보 조회 (GetDeviceInformation)
// ============================================================

static const char* SOAP_GET_DEVICE_INFO_TEMPLATE =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<soap:Body>"
    "<tds:GetDeviceInformation/>"
    "</soap:Body>"
    "</soap:Envelope>";

// 간단한 HTTP POST (ONVIF용)
static std::string http_post(const std::string& url, const std::string& body, int timeout_ms) {
    // URL 파싱: http://ip:port/path
    std::string host, path;
    uint16_t port = 80;

    auto start = url.find("://");
    if (start == std::string::npos) return "";
    start += 3;

    auto pathPos = url.find('/', start);
    if (pathPos == std::string::npos) {
        path = "/";
        host = url.substr(start);
    } else {
        path = url.substr(pathPos);
        host = url.substr(start, pathPos - start);
    }

    auto colonPos = host.find(':');
    if (colonPos != std::string::npos) {
        port = static_cast<uint16_t>(std::stoi(host.substr(colonPos + 1)));
        host = host.substr(0, colonPos);
    }

    // TCP 소켓 연결
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return "";
#else
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return "";
#endif

    // 타임아웃 설정
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return "";
    }

    // HTTP 요청 생성
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host << ":" << port << "\r\n"
        << "Content-Type: application/soap+xml; charset=utf-8\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;

    std::string request = req.str();
    send(sock, request.c_str(), static_cast<int>(request.size()), 0);

    // 응답 수신
    std::string response;
    char buf[4096];
    while (true) {
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        response += buf;
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    // HTTP body 추출 (헤더 이후)
    auto headerEnd = response.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
        return response.substr(headerEnd + 4);
    }

    return response;
}

bool onvif_get_device_info(const std::string& service_url, OnvifDevice& device) {
    std::string response = http_post(service_url, SOAP_GET_DEVICE_INFO_TEMPLATE, 3000);
    if (response.empty()) return false;

    pugi::xml_document doc;
    if (!doc.load_string(response.c_str())) return false;

    // 재귀적으로 필드를 찾는 walker
    struct InfoFinder : pugi::xml_tree_walker {
        std::string manufacturer;
        std::string model;
        std::string firmware;

        bool for_each(pugi::xml_node& node) override {
            std::string name = node.name();
            if (name.find("Manufacturer") != std::string::npos) {
                manufacturer = node.text().get();
            } else if (name.find("Model") != std::string::npos) {
                model = node.text().get();
            } else if (name.find("FirmwareVersion") != std::string::npos) {
                firmware = node.text().get();
            }
            return true;
        }
    };

    InfoFinder finder;
    doc.traverse(finder);

    if (finder.manufacturer.empty() && finder.model.empty()) {
        return false;
    }

    device.manufacturer = finder.manufacturer;
    device.model = finder.model;
    device.firmware_version = finder.firmware;

    return true;
}
