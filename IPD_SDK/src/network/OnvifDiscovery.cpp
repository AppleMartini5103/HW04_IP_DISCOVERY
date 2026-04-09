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

static std::string extract_xaddrs(const std::string& xml) {
    pugi::xml_document doc;
    if (!doc.load_string(xml.c_str())) return "";

    struct XAddrsFinder : pugi::xml_tree_walker {
        std::string result;
        bool for_each(pugi::xml_node& node) override {
            std::string name = node.name();
            if (name.find("XAddrs") != std::string::npos) {
                result = node.text().get();
                return false;
            }
            return true;
        }
    };

    XAddrsFinder finder;
    doc.traverse(finder);

    std::string addrs = finder.result;
    auto space = addrs.find(' ');
    if (space != std::string::npos) {
        addrs = addrs.substr(0, space);
    }

    return addrs;
}

static std::string extract_ip_from_url(const std::string& url) {
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

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    struct sockaddr_in dest = {};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(WS_DISCOVERY_PORT);
    inet_pton(AF_INET, WS_DISCOVERY_ADDR, &dest.sin_addr);

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
        if (recvLen <= 0) break;

        buf[recvLen] = '\0';
        std::string xml(buf, recvLen);
        std::string xaddrs = extract_xaddrs(xml);

        if (!xaddrs.empty()) {
            OnvifDevice dev;
            dev.service_url = xaddrs;
            dev.ip = extract_ip_from_url(xaddrs);

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
// ONVIF GetDeviceInformation
// ============================================================

static const char* SOAP_GET_DEVICE_INFO =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\""
    " xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
    "<soap:Body>"
    "<tds:GetDeviceInformation/>"
    "</soap:Body>"
    "</soap:Envelope>";

static std::string http_post(const std::string& url, const std::string& body, int timeout_ms) {
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

#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return "";
    DWORD tvs = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tvs), sizeof(tvs));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tvs), sizeof(tvs));
#else
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return "";
    struct timeval tvs;
    tvs.tv_sec = timeout_ms / 1000;
    tvs.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tvs, sizeof(tvs));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tvs, sizeof(tvs));
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

    std::string response;
    char rbuf[4096];
    while (true) {
        int n = recv(sock, rbuf, sizeof(rbuf) - 1, 0);
        if (n <= 0) break;
        rbuf[n] = '\0';
        response += rbuf;
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    auto headerEnd = response.find("\r\n\r\n");
    if (headerEnd != std::string::npos) {
        return response.substr(headerEnd + 4);
    }
    return response;
}

bool onvif_get_device_info(const std::string& service_url, OnvifDevice& device) {
    std::string response = http_post(service_url, SOAP_GET_DEVICE_INFO, 3000);
    if (response.empty()) return false;

    pugi::xml_document doc;
    if (!doc.load_string(response.c_str())) return false;

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

    if (finder.manufacturer.empty() && finder.model.empty()) return false;

    device.manufacturer = finder.manufacturer;
    device.model = finder.model;
    device.firmware_version = finder.firmware;
    return true;
}
