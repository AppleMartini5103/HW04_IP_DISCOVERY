#include "NetworkScanner.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#endif

#include <cstdio>
#include <thread>
#include <mutex>
#include <unordered_map>

// ============================================================
// OUI 벤더 테이블 (주요 제조사)
// ============================================================
struct OuiEntry { const char* prefix; const char* vendor; };
static const OuiEntry OUI_TABLE[] = {
    {"00:09:18", "Samsung Techwin"}, {"00:0B:82", "Grandstream"},
    {"00:0E:8F", "Cisco"},           {"00:11:32", "Synology"},
    {"00:17:88", "Philips Hue"},     {"00:1A:07", "Arecont Vision"},
    {"00:1C:7E", "Toshiba"},         {"00:20:6B", "GSD (Radar)"},
    {"00:40:84", "Honeywell"},       {"00:50:C2", "IEEE Regist."},
    {"00:72:EE", "iRobot/LG"},       {"00:80:F0", "Panasonic"},
    {"00:A5:54", "Intel"},           {"00:E0:4C", "Realtek"},
    {"08:9D:F4", "Compal"},          {"10:5F:AD", "Cisco Meraki"},
    {"14:02:EC", "TP-Link"},         {"18:53:E0", "Apple"},
    {"24:B2:B9", "Samsung"},         {"2C:33:11", "Axis"},
    {"34:3A:20", "Hanwha Techwin"},  {"44:A3:BB", "Google"},
    {"48:B4:C3", "Hanwha Vision"},   {"58:86:94", "Intel"},
    {"5C:B4:7E", "Samsung"},         {"60:A5:E2", "Apple"},
    {"68:C6:AC", "Samsung"},         {"70:85:C2", "ASRock"},
    {"74:56:3C", "Goke"},            {"80:F3:DA", "Xiaomi"},
    {"84:7B:57", "Intel"},           {"84:BA:59", "Samsung"},
    {"84:C5:A6", "Intel"},           {"8C:B0:E9", "Samsung"},
    {"8C:E9:EE", "Xiaomi"},          {"90:09:D0", "Synology"},
    {"90:E2:BA", "Intel"},           {"90:E9:5E", "Samsung"},
    {"A4:0E:75", "Comtrend"},        {"A8:E5:39", "LG Electronics"},
    {"AC:71:2E", "ipTIME"},          {"B0:47:E9", "Samsung"},
    {"BC:45:5B", "Samsung"},         {"C8:15:4E", "Samsung"},
    {"C8:41:8A", "Samsung"},         {"C8:DD:6A", "Ruckus"},
    {"D0:50:99", "ASRock"},          {"D4:E9:8A", "Apple"},
    {"D8:77:66", "HP"},              {"DC:45:46", "Amazon"},
    {"DC:B7:AC", "Hanwha Techwin"},  {"E0:2B:E9", "Google"},
    {"E4:0D:36", "Intel"},           {"E4:1F:D5", "Samsung"},
    {"E4:30:22", "Hikvision"},       {"EC:8E:77", "Xiaomi"},
    {"F8:3D:C6", "Qualcomm"},
};
static const int OUI_TABLE_SIZE = sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0]);

// ============================================================
// 유틸리티
// ============================================================

std::string NetworkScanner::macToString(const uint8_t* mac, int len) {
    if (len < 6) return "";
    char buf[24];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

std::string NetworkScanner::ipToString(uint32_t ip_host) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_host);
    return inet_ntoa(addr);
}

uint32_t NetworkScanner::stringToIp(const std::string& ip_str) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_str.c_str(), &addr);
    return ntohl(addr.s_addr);
}

std::string NetworkScanner::lookupVendor(const std::string& mac) {
    if (mac.size() < 8) return "";
    std::string prefix = mac.substr(0, 8);  // "AA:BB:CC"
    for (int i = 0; i < OUI_TABLE_SIZE; i++) {
        if (prefix == OUI_TABLE[i].prefix) {
            return OUI_TABLE[i].vendor;
        }
    }
    return "";
}

// ============================================================
// 서브넷 파싱 (예: "192.168.0.0/24")
// ============================================================

bool NetworkScanner::parseSubnet(const char* subnet, LocalNetInfo& info) {
    if (!subnet) return false;

    std::string s = subnet;
    auto slash = s.find('/');
    if (slash == std::string::npos) return false;

    std::string ip_str = s.substr(0, slash);
    int prefix = std::stoi(s.substr(slash + 1));
    if (prefix < 8 || prefix > 30) return false;

    uint32_t ip_h = stringToIp(ip_str);
    uint32_t mask_h = (prefix == 0) ? 0 : (~0u << (32 - prefix));

    info.ip = ip_str;
    info.prefix_len = prefix;
    info.network_addr = ip_h & mask_h;
    info.broadcast_addr = info.network_addr | (~mask_h);

    // subnet_mask 문자열 생성
    struct in_addr mask_addr;
    mask_addr.s_addr = htonl(mask_h);
    info.subnet_mask = inet_ntoa(mask_addr);

    return true;
}

// ============================================================
// Windows 구현
// ============================================================

#ifdef _WIN32

bool NetworkScanner::getLocalNetInfo(LocalNetInfo& info) {
    ULONG bufLen = 0;
    GetAdaptersInfo(nullptr, &bufLen);
    if (bufLen == 0) return false;

    std::vector<uint8_t> buf(bufLen);
    auto* adapters = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());

    if (GetAdaptersInfo(adapters, &bufLen) != NO_ERROR) return false;

    for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
        std::string gw = adapter->GatewayList.IpAddress.String;
        if (gw.empty() || gw == "0.0.0.0") continue;

        info.ip = adapter->IpAddressList.IpAddress.String;
        info.subnet_mask = adapter->IpAddressList.IpMask.String;

        uint32_t ip_h = stringToIp(info.ip);
        uint32_t mask_h = stringToIp(info.subnet_mask);

        info.network_addr = ip_h & mask_h;
        info.broadcast_addr = info.network_addr | (~mask_h);

        info.prefix_len = 0;
        uint32_t m = mask_h;
        while (m & 0x80000000) { info.prefix_len++; m <<= 1; }

        return true;
    }
    return false;
}

void NetworkScanner::readArpCache(const LocalNetInfo& info, uint32_t myIp, std::vector<ScanEntry>& results) {
    ULONG tableSize = 0;
    GetIpNetTable(nullptr, &tableSize, FALSE);
    if (tableSize == 0) return;

    std::vector<uint8_t> tableBuf(tableSize);
    auto* table = reinterpret_cast<MIB_IPNETTABLE*>(tableBuf.data());

    if (GetIpNetTable(table, &tableSize, FALSE) != NO_ERROR) return;

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        auto& row = table->table[i];

        if (row.dwType != MIB_IPNET_TYPE_DYNAMIC &&
            row.dwType != MIB_IPNET_TYPE_STATIC) continue;

        uint32_t ip_h = ntohl(row.dwAddr);

        if (ip_h <= info.network_addr || ip_h >= info.broadcast_addr) continue;
        if (ip_h == myIp) continue;
        if (row.dwPhysAddrLen < 6) continue;

        ScanEntry entry;
        entry.ip = ipToString(ip_h);
        entry.mac = macToString(row.bPhysAddr, static_cast<int>(row.dwPhysAddrLen));
        results.push_back(entry);
    }
}

bool NetworkScanner::tcpProbe(uint32_t ip_h, uint16_t port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip_h);

    connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    fd_set writefds, errfds;
    FD_ZERO(&writefds);
    FD_ZERO(&errfds);
    FD_SET(sock, &writefds);
    FD_SET(sock, &errfds);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200 * 1000;

    bool is_open = false;
    int ret = select(static_cast<int>(sock) + 1, nullptr, &writefds, &errfds, &tv);
    if (ret > 0 && FD_ISSET(sock, &writefds) && !FD_ISSET(sock, &errfds)) {
        int err = 0;
        int errlen = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
        is_open = (err == 0);
    }

    closesocket(sock);
    return is_open;
}

bool NetworkScanner::scan(const LocalNetInfo& info, const std::vector<uint16_t>& ports,
                           std::vector<ScanEntry>& results, std::atomic<bool>& cancelled) {
    results.clear();

    uint32_t start = info.network_addr + 1;
    uint32_t end = info.broadcast_addr;
    uint32_t total = end - start;

    if (total == 0 || total > 1024) return false;

    uint32_t myIp = stringToIp(info.ip);

    // probe용 포트 (ports 비어있으면 80)
    std::vector<uint16_t> probePorts = ports.empty() ? std::vector<uint16_t>{80} : ports;
    bool recordPorts = !ports.empty();

    int batchSize = static_cast<int>(std::thread::hardware_concurrency()) * 2;
    if (batchSize < 4) batchSize = 4;
    if (batchSize > 16) batchSize = 16;

    // ===== TCP probe (다중 포트) =====
    struct ProbeResult {
        uint32_t ip_h;
        std::set<uint16_t> open_ports;
    };
    std::vector<ProbeResult> probeResults(total);
    for (uint32_t i = 0; i < total; i++) {
        probeResults[i].ip_h = start + i;
    }

    for (uint32_t batchStart = 0; batchStart < total && !cancelled; batchStart += batchSize) {
        uint32_t batchEnd = batchStart + batchSize;
        if (batchEnd > total) batchEnd = total;

        std::vector<std::thread> threads;
        for (uint32_t i = batchStart; i < batchEnd; i++) {
            uint32_t ip_h = probeResults[i].ip_h;
            if (ip_h == myIp) continue;

            threads.emplace_back([this, ip_h, &probePorts, recordPorts, &probeResults, i]() {
                for (uint16_t port : probePorts) {
                    if (tcpProbe(ip_h, port)) {
                        if (recordPorts) {
                            probeResults[i].open_ports.insert(port);
                        }
                    }
                }
            });
        }
        for (auto& th : threads) {
            th.join();
        }
    }

    if (cancelled) return false;

    // ===== ARP 캐시 읽기 =====
    readArpCache(info, myIp, results);

    // ===== 포트 결과 매칭 (해시맵으로 O(1) 조회) =====
    if (recordPorts) {
        std::unordered_map<uint32_t, std::set<uint16_t>> portMap;
        for (const auto& pr : probeResults) {
            if (!pr.open_ports.empty()) {
                portMap[pr.ip_h] = pr.open_ports;
            }
        }
        for (auto& entry : results) {
            auto it = portMap.find(stringToIp(entry.ip));
            if (it != portMap.end()) {
                entry.open_ports = it->second;
            }
        }
    }

    return true;
}

bool NetworkScanner::scanHost(const std::string& ip, const std::vector<uint16_t>& ports,
                               ScanEntry& result) {
    result = {};
    result.ip = ip;

    uint32_t ip_h = stringToIp(ip);

    // MAC 조회 (SendARP)
    IPAddr destIp = htonl(ip_h);
    ULONG macAddr[2] = {0};
    ULONG macLen = 6;

    DWORD ret = SendARP(destIp, 0, macAddr, &macLen);
    if (ret == NO_ERROR && macLen > 0) {
        result.mac = macToString(reinterpret_cast<uint8_t*>(macAddr), static_cast<int>(macLen));
    }

    // 포트 스캔
    for (uint16_t port : ports) {
        if (tcpProbe(ip_h, port)) {
            result.open_ports.insert(port);
        }
    }

    return true;
}

#else

bool NetworkScanner::getLocalNetInfo(LocalNetInfo& info) { return false; }

bool NetworkScanner::parseSubnet(const char* subnet, LocalNetInfo& info) { return false; }

bool NetworkScanner::scan(const LocalNetInfo& info, const std::vector<uint16_t>& ports,
                           std::vector<ScanEntry>& results, std::atomic<bool>& cancelled) { return false; }

bool NetworkScanner::scanHost(const std::string& ip, const std::vector<uint16_t>& ports,
                               ScanEntry& result) { return false; }

#endif
