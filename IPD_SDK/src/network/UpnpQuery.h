#pragma once

#include <string>

struct UpnpIgdInfo {
    bool        found;
    std::string device_name;
    std::string local_ip;
    std::string wan_ip;
    std::string status;
    std::string gateway_ip;
};

bool upnp_query_igd(int timeout_ms, UpnpIgdInfo& info);
