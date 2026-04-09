#pragma once

#include "IpDiscoverySdk.h"
#include "UpnpQuery.h"
#include "OnvifDiscovery.h"

#include <string>
#include <vector>

void classify_device(
    ipd_device_t& device,
    const UpnpIgdInfo& igdInfo,
    const std::vector<OnvifDevice>& onvifDevices
);
