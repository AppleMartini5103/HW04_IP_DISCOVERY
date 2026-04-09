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

bool onvif_discover(int timeout_ms, std::vector<OnvifDevice>& devices);
bool onvif_get_device_info(const std::string& service_url, OnvifDevice& device);
