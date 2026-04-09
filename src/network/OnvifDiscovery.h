#pragma once

#include <string>
#include <vector>

struct OnvifDevice {
    std::string ip;
    std::string service_url;    // ONVIF device service URL
    std::string manufacturer;
    std::string model;
    std::string firmware_version;
};

// WS-Discovery로 ONVIF 카메라 검색
bool onvif_discover(int timeout_ms, std::vector<OnvifDevice>& devices);

// 개별 카메라 상세 정보 조회 (GetDeviceInformation)
bool onvif_get_device_info(const std::string& service_url, OnvifDevice& device);
