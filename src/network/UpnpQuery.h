#pragma once

#include <string>

struct UpnpIgdInfo {
    bool        found;
    std::string device_name;
    std::string local_ip;
    std::string wan_ip;
    std::string status;         // "Connected", "Disconnected" 등
    std::string gateway_ip;     // IGD의 IP 주소
};

// UPnP IGD 검색 및 상세 정보 조회
bool upnp_query_igd(int timeout_ms, UpnpIgdInfo& info);
