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

// MAC 바이트 배열을 "AA:BB:CC:DD:EE:FF" 문자열로 변환
static std::string mac_to_string(const uint8_t* mac, int len) {
    if (len < 6) return "";
    char buf[24];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

// IP (host order uint32) → "x.x.x.x" 문자열
static std::string ip_to_string(uint32_t ip_host) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_host);
    return inet_ntoa(addr);
}

// "x.x.x.x" 문자열 → host order uint32
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

    // 게이트웨이가 설정된 첫 번째 어댑터 선택
    for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
        std::string gw = adapter->GatewayList.IpAddress.String;
        if (gw.empty() || gw == "0.0.0.0") continue;

        info.ip = adapter->IpAddressList.IpAddress.String;
        info.subnet_mask = adapter->IpAddressList.IpMask.String;

        uint32_t ip_h = string_to_ip(info.ip);
        uint32_t mask_h = string_to_ip(info.subnet_mask);

        info.network_addr = ip_h & mask_h;
        info.broadcast_addr = info.network_addr | (~mask_h);

        // prefix 길이 계산
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

// 단일 IP에 대한 ARP 요청
static bool arp_probe_single(uint32_t ip_h, ArpEntry& entry) {
    IPAddr destIp = htonl(ip_h);
    ULONG macAddr[2] = {0};
    ULONG macLen = 6;

    DWORD ret = SendARP(destIp, 0, macAddr, &macLen);
    if (ret == NO_ERROR && macLen > 0) {
        entry.ip = ip_to_string(ip_h);
        entry.mac = mac_to_string(reinterpret_cast<uint8_t*>(macAddr), static_cast<int>(macLen));
        return true;
    }
    return false;
}

bool arp_scan_subnet(const LocalNetInfo& info, std::vector<ArpEntry>& results) {
    results.clear();

    uint32_t start = info.network_addr + 1;
    uint32_t end = info.broadcast_addr;
    uint32_t total = end - start;

    if (total == 0 || total > 1024) return false;

    // 스레드 수 제한 (최대 64개)
    const int max_threads = 64;
    int thread_count = (total < static_cast<uint32_t>(max_threads)) ? static_cast<int>(total) : max_threads;

    std::mutex results_mutex;
    std::vector<std::thread> threads;

    // IP 범위를 스레드에 분배
    auto worker = [&](uint32_t range_start, uint32_t range_end) {
        for (uint32_t ip_h = range_start; ip_h < range_end; ip_h++) {
            ArpEntry entry;
            if (arp_probe_single(ip_h, entry)) {
                std::lock_guard<std::mutex> lock(results_mutex);
                results.push_back(entry);
            }
        }
    };

    uint32_t chunk = total / thread_count;
    uint32_t remainder = total % thread_count;

    uint32_t current = start;
    for (int t = 0; t < thread_count; t++) {
        uint32_t range_end = current + chunk + (t < static_cast<int>(remainder) ? 1 : 0);
        if (range_end > end) range_end = end;
        threads.emplace_back(worker, current, range_end);
        current = range_end;
    }

    for (auto& th : threads) {
        th.join();
    }

    return true;
}

#else

// Linux 구현 (나중에)
bool arp_get_local_net_info(LocalNetInfo& info) {
    return false;
}

bool arp_scan_subnet(const LocalNetInfo& info, std::vector<ArpEntry>& results) {
    return false;
}

#endif
