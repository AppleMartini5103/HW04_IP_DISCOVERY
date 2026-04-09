#pragma once

#include "IpDiscoverySdk.h"
#include "UpnpQuery.h"
#include "OnvifDiscovery.h"

#include <string>
#include <vector>

// ARP 스캔 결과 + 프로토콜 조회 결과를 바탕으로 디바이스 타입 판별
void classify_device(
    ipd_device_t& device,
    const UpnpIgdInfo& igdInfo,
    const std::vector<OnvifDevice>& onvifDevices
);
