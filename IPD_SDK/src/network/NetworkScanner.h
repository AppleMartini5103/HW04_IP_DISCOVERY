#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ScanEntry {
    std::string ip;
    std::string mac;
    bool        port_open;   // port > 0일 때 해당 포트 오픈 여부
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
    // 로컬 네트워크 정보 자동 감지
    bool getLocalNetInfo(LocalNetInfo& info);

    // 서브넷 스캔 (TCP probe → ARP 캐시 읽기 + 포트 오픈 확인 통합)
    // port=0: 호스트 존재 여부만 (내부적으로 port 80 사용)
    // port>0: 해당 포트로 probe + 오픈 여부 기록
    bool scan(const LocalNetInfo& info, uint16_t port, std::vector<ScanEntry>& results);

private:
    static std::string macToString(const uint8_t* mac, int len);
    static std::string ipToString(uint32_t ip_host);
    static uint32_t    stringToIp(const std::string& ip_str);

#ifdef _WIN32
    void readArpCache(const LocalNetInfo& info, uint32_t myIp, std::vector<ScanEntry>& results);
    void tcpProbe(uint32_t ip_h, uint16_t port, bool recordPort, bool& portOpen);
#endif
};
