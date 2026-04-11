#pragma once

#include <string>
#include <vector>

struct OnvifDevice {
    std::string ip;
    std::string service_url;
    std::string manufacturer;
    std::string model;
    std::string firmware_version;
};

class OnvifDiscovery {
public:
    bool discover(int timeout_ms, std::vector<OnvifDevice>& devices);
    bool getDeviceInfo(const std::string& service_url, OnvifDevice& device);

private:
    static std::string extractXAddrs(const std::string& xml);
    static std::string extractIpFromUrl(const std::string& url);
    static std::string httpPost(const std::string& url, const std::string& body, int timeout_ms);
};
