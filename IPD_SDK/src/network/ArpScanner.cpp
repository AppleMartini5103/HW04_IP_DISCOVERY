#include "ArpScanner.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
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
#include <atomic>

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

// ICMP ping으로 호스트 존재 여부 빠르게 확인 (타임아웃 짧게)
static bool ping_check(uint32_t ip_h, int timeout_ms) {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return false;

    IPAddr destIp = htonl(ip_h);
    char sendData[] = "ping";
    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData) + 8;
    std::vector<uint8_t> replyBuf(replySize);

    DWORD ret = IcmpSendEcho(hIcmp, destIp, sendData, sizeof(sendData),
                              nullptr, replyBuf.data(), replySize, static_cast<DWORD>(timeout_ms));

    IcmpCloseHandle(hIcmp);
    return (ret > 0);
}

// SendARP로 MAC 주소 획득
static bool get_mac_by_arp(uint32_t ip_h, std::string& mac) {
    IPAddr destIp = htonl(ip_h);
    ULONG macAddr[2] = {0};
    ULONG macLen = 6;

    DWORD ret = SendARP(destIp, 0, macAddr, &macLen);
    if (ret == NO_ERROR && macLen > 0) {
        mac = mac_to_string(reinterpret_cast<uint8_t*>(macAddr), static_cast<int>(macLen));
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

    uint32_t my_ip = string_to_ip(info.ip);

    // 스레드 수 = CPU 코어 수 기반 (최소 4, 최대 32)
    int hw_threads = static_cast<int>(std::thread::hardware_concurrency());
    if (hw_threads < 4) hw_threads = 4;
    if (hw_threads > 32) hw_threads = 32;

    // ===== 1단계: ICMP ping으로 살아있는 호스트 빠르게 탐지 =====
    std::vector<uint32_t> alive_hosts;
    std::mutex alive_mutex;

    {
        std::vector<std::thread> threads;
        int thread_count = (total < static_cast<uint32_t>(hw_threads)) ? static_cast<int>(total) : hw_threads;
        uint32_t chunk = total / thread_count;
        uint32_t remainder = total % thread_count;

        uint32_t current = start;
        for (int t = 0; t < thread_count; t++) {
            uint32_t range_end = current + chunk + (t < static_cast<int>(remainder) ? 1 : 0);
            if (range_end > end) range_end = end;

            threads.emplace_back([&, current, range_end]() {
                for (uint32_t ip_h = current; ip_h < range_end; ip_h++) {
                    if (ip_h == my_ip) continue;
                    if (ping_check(ip_h, 100)) {
                        std::lock_guard<std::mutex> lock(alive_mutex);
                        alive_hosts.push_back(ip_h);
                    }
                }
            });
            current = range_end;
        }

        for (auto& th : threads) {
            th.join();
        }
    }

    if (alive_hosts.empty()) return true;

    // ===== 2단계: 살아있는 호스트에만 SendARP로 MAC 획득 =====
    std::mutex results_mutex;

    {
        std::vector<std::thread> threads;
        for (uint32_t ip_h : alive_hosts) {
            threads.emplace_back([&, ip_h]() {
                std::string mac;
                if (get_mac_by_arp(ip_h, mac)) {
                    ArpEntry entry;
                    entry.ip = ip_to_string(ip_h);
                    entry.mac = mac;
                    std::lock_guard<std::mutex> lock(results_mutex);
                    results.push_back(entry);
                }
            });
        }

        for (auto& th : threads) {
            th.join();
        }
    }

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
