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
#include <set>

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

    if (GetAdaptersInfo(adapters, &bufLen) != NO_ERROR) {
        return false;
    }

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
        while (m & 0x80000000) {
            info.prefix_len++;
            m <<= 1;
        }

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
        entry.port_open = false;
        results.push_back(entry);
    }
}

void NetworkScanner::tcpProbe(uint32_t ip_h, uint16_t port, bool recordPort, bool& portOpen) {
    portOpen = false;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return;

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
    tv.tv_usec = 200 * 1000;  // 200ms

    int ret = select(static_cast<int>(sock) + 1, nullptr, &writefds, &errfds, &tv);
    if (recordPort && ret > 0 && FD_ISSET(sock, &writefds) && !FD_ISSET(sock, &errfds)) {
        int err = 0;
        int errlen = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
        portOpen = (err == 0);
    }

    closesocket(sock);
}

bool NetworkScanner::scan(const LocalNetInfo& info, uint16_t port, std::vector<ScanEntry>& results) {
    results.clear();

    uint32_t start = info.network_addr + 1;
    uint32_t end = info.broadcast_addr;
    uint32_t total = end - start;

    if (total == 0 || total > 1024) return false;

    uint32_t myIp = stringToIp(info.ip);

    // probe에 사용할 포트 (port=0이면 80)
    uint16_t probePort = (port > 0) ? port : 80;
    bool recordPort = (port > 0);

    // 스레드 수 = 코어수 * 2 (최소 4, 최대 16)
    int batchSize = static_cast<int>(std::thread::hardware_concurrency()) * 2;
    if (batchSize < 4) batchSize = 4;
    if (batchSize > 16) batchSize = 16;

    // ===== TCP probe → ARP 캐시 유도 + 포트 오픈 동시 확인 =====
    // IP별 포트 오픈 결과 저장
    struct ProbeResult {
        uint32_t ip_h;
        bool     port_open;
    };
    std::vector<ProbeResult> probeResults(total);
    for (uint32_t i = 0; i < total; i++) {
        probeResults[i].ip_h = start + i;
        probeResults[i].port_open = false;
    }

    for (uint32_t batchStart = 0; batchStart < total; batchStart += batchSize) {
        uint32_t batchEnd = batchStart + batchSize;
        if (batchEnd > total) batchEnd = total;

        std::vector<std::thread> threads;
        for (uint32_t i = batchStart; i < batchEnd; i++) {
            uint32_t ip_h = probeResults[i].ip_h;
            if (ip_h == myIp) continue;

            threads.emplace_back([this, ip_h, probePort, recordPort, &probeResults, i]() {
                tcpProbe(ip_h, probePort, recordPort, probeResults[i].port_open);
            });
        }
        for (auto& th : threads) {
            th.join();
        }
    }

    // ===== ARP 캐시 읽기 =====
    readArpCache(info, myIp, results);

    // ===== 포트 오픈 결과 매칭 =====
    if (recordPort) {
        // IP → port_open 매핑
        std::set<std::string> openIps;
        for (const auto& pr : probeResults) {
            if (pr.port_open) {
                openIps.insert(ipToString(pr.ip_h));
            }
        }

        for (auto& entry : results) {
            if (openIps.count(entry.ip)) {
                entry.port_open = true;
            }
        }
    }

    return true;
}

#else

bool NetworkScanner::getLocalNetInfo(LocalNetInfo& info) {
    return false;
}

bool NetworkScanner::scan(const LocalNetInfo& info, uint16_t port, std::vector<ScanEntry>& results) {
    return false;
}

#endif
