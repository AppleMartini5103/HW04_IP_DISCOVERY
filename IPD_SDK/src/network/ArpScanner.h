#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ArpEntry {
    std::string ip;
    std::string mac;
};

// 로컬 네트워크 정보
struct LocalNetInfo {
    std::string ip;
    std::string subnet_mask;
    uint32_t    network_addr;   // 네트워크 주소 (host order)
    uint32_t    broadcast_addr; // 브로드캐스트 주소 (host order)
    int         prefix_len;     // 서브넷 prefix (예: 24)
};

// 로컬 네트워크 정보 자동 감지
bool arp_get_local_net_info(LocalNetInfo& info);

// 서브넷 ARP 스캔 (살아있는 호스트 반환)
bool arp_scan_subnet(const LocalNetInfo& info, std::vector<ArpEntry>& results);
