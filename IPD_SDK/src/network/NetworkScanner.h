#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <set>

struct ScanEntry {
    std::string          ip;
    std::string          mac;
    std::set<uint16_t>   open_ports;
};

struct LocalNetInfo {
    std::string ip;
    std::string subnet_mask;
    uint32_t    network_addr;
    uint32_t    broadcast_addr;
    int         prefix_len;
};

class NetworkScanner {
public:
    bool getLocalNetInfo(LocalNetInfo& info);

    // 서브넷 지정으로 LocalNetInfo 생성
    bool parseSubnet(const char* subnet, LocalNetInfo& info);

    // 다중 포트 스캔 지원
    // ports 비어있으면 호스트 존재 확인만 (port 80)
    bool scan(const LocalNetInfo& info, const std::vector<uint16_t>& ports,
              std::vector<ScanEntry>& results, std::atomic<bool>& cancelled);

    // 단일 IP 스캔 (재스캔용)
    bool scanHost(const std::string& ip, const std::vector<uint16_t>& ports,
                  ScanEntry& result);

    // MAC 벤더 조회 (OUI 기반)
    static std::string lookupVendor(const std::string& mac);

private:
    static std::string macToString(const uint8_t* mac, int len);
    static std::string ipToString(uint32_t ip_host);
    static uint32_t    stringToIp(const std::string& ip_str);

#ifdef _WIN32
    void readArpCache(const LocalNetInfo& info, uint32_t myIp, std::vector<ScanEntry>& results);
    bool tcpProbe(uint32_t ip_h, uint16_t port);
#endif
};
