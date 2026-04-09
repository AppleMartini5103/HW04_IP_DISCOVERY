#include "DeviceClassifier.h"

#include <cstring>
#include <cstdio>

static const uint16_t RADAR_PORTS[] = { 5000, 8899 };
static const int RADAR_PORT_COUNT = sizeof(RADAR_PORTS) / sizeof(RADAR_PORTS[0]);

static bool is_radar_port(uint16_t port) {
    for (int i = 0; i < RADAR_PORT_COUNT; i++) {
        if (RADAR_PORTS[i] == port) return true;
    }
    return false;
}

void classify_device(
    ipd_device_t& device,
    const UpnpIgdInfo& igdInfo,
    const std::vector<OnvifDevice>& onvifDevices
) {
    std::string deviceIp = device.ip;

    // 1순위: UPnP IGD
    if (igdInfo.found && igdInfo.gateway_ip == deviceIp) {
        device.type = IPD_DEVICE_IGD;
        strncpy(device.type_name, "IGD", sizeof(device.type_name) - 1);
        strncpy(device.name, "Gateway", sizeof(device.name) - 1);

        char detail[256] = {};
        snprintf(detail, sizeof(detail), "WAN:%s Status:%s",
                 igdInfo.wan_ip.c_str(), igdInfo.status.c_str());
        strncpy(device.detail, detail, sizeof(device.detail) - 1);
        return;
    }

    // 2순위: ONVIF Camera
    for (const auto& cam : onvifDevices) {
        if (cam.ip == deviceIp) {
            device.type = IPD_DEVICE_CAMERA;
            strncpy(device.type_name, "Camera", sizeof(device.type_name) - 1);
            strncpy(device.manufacturer, cam.manufacturer.c_str(), sizeof(device.manufacturer) - 1);
            strncpy(device.model, cam.model.c_str(), sizeof(device.model) - 1);

            char detail[256] = {};
            if (!cam.firmware_version.empty()) {
                snprintf(detail, sizeof(detail), "FW:%s", cam.firmware_version.c_str());
            }
            strncpy(device.detail, detail, sizeof(device.detail) - 1);

            if (!cam.manufacturer.empty()) {
                strncpy(device.name, cam.manufacturer.c_str(), sizeof(device.name) - 1);
                if (!cam.model.empty()) {
                    strncat(device.name, " ", sizeof(device.name) - strlen(device.name) - 1);
                    strncat(device.name, cam.model.c_str(), sizeof(device.name) - strlen(device.name) - 1);
                }
            }
            return;
        }
    }

    // 3순위: Radar
    for (int i = 0; i < device.port_count; i++) {
        if (is_radar_port(device.ports[i])) {
            device.type = IPD_DEVICE_RADAR;
            strncpy(device.type_name, "Radar", sizeof(device.type_name) - 1);
            strncpy(device.name, "Radar", sizeof(device.name) - 1);
            return;
        }
    }

    // 4순위: Host
    if (device.port_count > 0) {
        device.type = IPD_DEVICE_HOST;
        strncpy(device.type_name, "Host", sizeof(device.type_name) - 1);
        return;
    }

    // 기본: Unknown
    device.type = IPD_DEVICE_UNKNOWN;
    strncpy(device.type_name, "Unknown", sizeof(device.type_name) - 1);
}
