#include "ArpScanner.h"

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
#include <cstring>
#endif

#include <cstdio>
#include <thread>
#include <mutex>
#include <chrono>

static std::string mac_to_string(const uint8_t* mac, int len) {
    if (len < 6) return "";
    char buf[24];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static std::string ip_to_string(uint32_t ip_host) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_host);
    return inet_ntoa(addr);
}

static uint32_t string_to_ip(const std::string& ip_str) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_str.c_str(), &addr);
    return ntohl(addr.s_addr);
}

#ifdef _WIN32

bool arp_get_local_net_info(LocalNetInfo& info) {
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

        uint32_t ip_h = string_to_ip(info.ip);
        uint32_t mask_h = string_to_ip(info.subnet_mask);

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

// OS ARP 캐시에서 서브넷 내 호스트 읽기
static void read_arp_cache(const LocalNetInfo& info, uint32_t my_ip, std::vector<ArpEntry>& results) {
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
        if (ip_h == my_ip) continue;
        if (row.dwPhysAddrLen < 6) continue;

        ArpEntry entry;
        entry.ip = ip_to_string(ip_h);
        entry.mac = mac_to_string(row.bPhysAddr, static_cast<int>(row.dwPhysAddrLen));
        results.push_back(entry);
    }
}

// TCP connect로 호스트 생존 여부 확인 + ARP 캐시 갱신 유도
// RTS_Crosshair 방식 참고: 200ms 타임아웃, non-blocking connect
static void tcp_probe(uint32_t ip_h) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return;

    // non-blocking
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);  // 아무 포트나 OK — 목적은 ARP 유도
    addr.sin_addr.s_addr = htonl(ip_h);

    connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    // 200ms 대기 (TCP SYN → ARP 요청이 자동 발생)
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200 * 1000;  // 200ms

    select(static_cast<int>(sock) + 1, nullptr, &writefds, nullptr, &tv);

    closesocket(sock);
}

bool arp_scan_subnet(const LocalNetInfo& info, std::vector<ArpEntry>& results) {
    results.clear();

    uint32_t start = info.network_addr + 1;
    uint32_t end = info.broadcast_addr;
    uint32_t total = end - start;

    if (total == 0 || total > 1024) return false;

    uint32_t my_ip = string_to_ip(info.ip);

    // ===== 1단계: TCP probe로 ARP 캐시 채우기 =====
    // RTS_Crosshair 참고: 200ms 타임아웃, 다수 동시 연결
    // 배치 크기 = 코어 수 * 2 (최소 4, 최대 16)
    int batch_size = static_cast<int>(std::thread::hardware_concurrency()) * 2;
    if (batch_size < 4) batch_size = 4;
    if (batch_size > 16) batch_size = 16;

    for (uint32_t batch_start = start; batch_start < end; batch_start += batch_size) {
        uint32_t batch_end = batch_start + batch_size;
        if (batch_end > end) batch_end = end;

        std::vector<std::thread> threads;
        for (uint32_t ip_h = batch_start; ip_h < batch_end; ip_h++) {
            if (ip_h == my_ip) continue;
            threads.emplace_back(tcp_probe, ip_h);
        }
        for (auto& th : threads) {
            th.join();
        }
    }

    // ===== 2단계: ARP 캐시 읽기 =====
    read_arp_cache(info, my_ip, results);

    return true;
}

#else

bool arp_get_local_net_info(LocalNetInfo& info) {
    return false;
}

bool arp_scan_subnet(const LocalNetInfo& info, std::vector<ArpEntry>& results) {
    return false;
}

#endif
