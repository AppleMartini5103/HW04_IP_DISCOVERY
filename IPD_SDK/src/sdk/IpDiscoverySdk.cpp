#include "IpDiscoverySdk.h"
#include "info/version.h"
#include "network/NetworkScanner.h"
#include "network/OnvifDiscovery.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// ============================================================
// 내부 클래스: Winsock 관리 + 디바이스 판별 + 프로그레스
// ============================================================

class IpdContext {
public:
    static IpdContext& instance() {
        static IpdContext ctx;
        return ctx;
    }

    bool wsaInit() {
        std::lock_guard<std::mutex> lock(m_mutex);
#ifdef _WIN32
        if (m_wsaRefCount++ > 0) return true;
        WSADATA wsa;
        return (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#else
        return true;
#endif
    }

    void wsaCleanup() {
        std::lock_guard<std::mutex> lock(m_mutex);
#ifdef _WIN32
        if (--m_wsaRefCount <= 0) {
            WSACleanup();
            m_wsaRefCount = 0;
        }
#endif
    }

    void setProgressCallback(ipd_progress_cb cb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_progressCb = cb;
    }

    void reportProgress(int current, int total, const char* message) {
        ipd_progress_cb cb = nullptr;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            cb = m_progressCb;
        }
        if (cb) {
            cb(current, total, message);
        }
    }

    // 디바이스 타입 판별
    void classifyDevice(ipd_device_t& device, const std::vector<OnvifDevice>& onvifDevices) {
        std::string deviceIp = device.ip;

        // 1순위: ONVIF Camera
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

        // 2순위: Radar (포트 5000, 8899)
        static const uint16_t RADAR_PORTS[] = { 5000, 8899 };
        for (int i = 0; i < device.port_count; i++) {
            for (uint16_t rp : RADAR_PORTS) {
                if (device.ports[i] == rp) {
                    device.type = IPD_DEVICE_RADAR;
                    strncpy(device.type_name, "Radar", sizeof(device.type_name) - 1);
                    strncpy(device.name, "Radar", sizeof(device.name) - 1);
                    return;
                }
            }
        }

        // 3순위: Host (포트 열려있음)
        if (device.port_count > 0) {
            device.type = IPD_DEVICE_HOST;
            strncpy(device.type_name, "Host", sizeof(device.type_name) - 1);
            return;
        }

        // 기본: Unknown
        device.type = IPD_DEVICE_UNKNOWN;
        strncpy(device.type_name, "Unknown", sizeof(device.type_name) - 1);
    }

private:
    IpdContext() = default;
    std::mutex m_mutex;
    ipd_progress_cb m_progressCb = nullptr;
    int m_wsaRefCount = 0;
};

// ============================================================
// 공개 API 구현
// ============================================================

void ipd_get_version(ipd_version_t* version) {
    if (!version) return;

    version->major = IPD_SDK_VERSION_MAJOR;
    version->minor = IPD_SDK_VERSION_MINOR;
    version->patch = IPD_SDK_VERSION_PATCH;
    version->name = IPD_SDK_NAME;
    version->manufacturer = IPD_SDK_MANUFACTURER;
}

int ipd_discover(ipd_search_flag_t flags, int timeout_ms, uint16_t port, ipd_result_t* result) {
    if (!result) return IPD_ERROR_INVALID_ARGS;

    memset(result, 0, sizeof(ipd_result_t));

    auto& ctx = IpdContext::instance();
    if (!ctx.wsaInit()) return IPD_ERROR_SOCKET;

    // ========== 로컬 네트워크 정보 감지 ==========
    NetworkScanner scanner;
    LocalNetInfo netInfo;
    if (!scanner.getLocalNetInfo(netInfo)) {
        ctx.wsaCleanup();
        return IPD_ERROR_SOCKET;
    }

    strncpy(result->local_ip, netInfo.ip.c_str(), sizeof(result->local_ip) - 1);

    char subnet_str[32];
    snprintf(subnet_str, sizeof(subnet_str), "%s/%d", netInfo.ip.c_str(), netInfo.prefix_len);
    strncpy(result->subnet, subnet_str, sizeof(result->subnet) - 1);

    // 총 단계 수 계산
    int total_steps = 1;  // 네트워크 스캔
    if (flags & IPD_SEARCH_CAMERA) total_steps++;
    total_steps++;  // 타입 판별 + 정렬
    int current_step = 0;

    // ========== 1단계: 네트워크 스캔 (TCP probe + ARP 캐시 + 포트 오픈 확인) ==========
    {
        char msg[128];
        snprintf(msg, sizeof(msg), "Network scanning %s/%d ...", netInfo.ip.c_str(), netInfo.prefix_len);
        ctx.reportProgress(current_step, total_steps, msg);
    }

    std::vector<ScanEntry> scanResults;
    if (!scanner.scan(netInfo, port, scanResults)) {
        ctx.wsaCleanup();
        return IPD_ERROR_SOCKET;
    }
    current_step++;

    if (scanResults.empty()) {
        ctx.reportProgress(total_steps, total_steps, "No hosts found");
        ctx.wsaCleanup();
        return IPD_SUCCESS;
    }

    {
        char msg[128];
        snprintf(msg, sizeof(msg), "Found %d hosts", static_cast<int>(scanResults.size()));
        ctx.reportProgress(current_step, total_steps, msg);
    }

    // ========== 결과 구조체 할당 ==========
    int count = static_cast<int>(scanResults.size());
    result->devices = static_cast<ipd_device_t*>(calloc(count, sizeof(ipd_device_t)));
    if (!result->devices) {
        ctx.wsaCleanup();
        return IPD_ERROR_MEMORY;
    }
    result->count = count;

    for (int i = 0; i < count; i++) {
        strncpy(result->devices[i].ip, scanResults[i].ip.c_str(), sizeof(result->devices[i].ip) - 1);
        strncpy(result->devices[i].mac, scanResults[i].mac.c_str(), sizeof(result->devices[i].mac) - 1);
        result->devices[i].type = IPD_DEVICE_UNKNOWN;
        strncpy(result->devices[i].type_name, "Unknown", sizeof(result->devices[i].type_name) - 1);

        if (scanResults[i].port_open && port > 0) {
            result->devices[i].ports[0] = port;
            result->devices[i].port_count = 1;
        }
    }

    // ========== 2단계: 프로토콜 상세 조회 (ONVIF, 병렬) ==========
    std::vector<OnvifDevice> onvifDevices;

    if (flags & IPD_SEARCH_CAMERA) {
        ctx.reportProgress(current_step, total_steps, "Discovering ONVIF cameras...");

        OnvifDiscovery onvif;
        int onvif_timeout = (timeout_ms > 2000) ? timeout_ms : 2000;
        onvif.discover(onvif_timeout, onvifDevices);

        if (!onvifDevices.empty()) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Querying %d ONVIF cameras...",
                     static_cast<int>(onvifDevices.size()));
            ctx.reportProgress(current_step, total_steps, msg);

            std::vector<std::thread> cam_threads;
            for (size_t i = 0; i < onvifDevices.size(); i++) {
                if (!onvifDevices[i].service_url.empty()) {
                    cam_threads.emplace_back([&onvif, &onvifDevices, i, onvif_timeout]() {
                        onvif.getDeviceInfo(onvifDevices[i].service_url, onvifDevices[i], onvif_timeout);
                    });
                }
            }
            for (auto& th : cam_threads) {
                th.join();
            }
        }
        current_step++;
    }

    // ========== 3단계: 디바이스 타입 판별 + IP 정렬 ==========
    ctx.reportProgress(current_step, total_steps, "Classifying devices...");

    for (int i = 0; i < count; i++) {
        ctx.classifyDevice(result->devices[i], onvifDevices);
    }

    // IP 오름차순 정렬
    std::sort(result->devices, result->devices + count,
        [](const ipd_device_t& a, const ipd_device_t& b) {
            uint32_t ip_a = 0, ip_b = 0;
            struct in_addr addr;
            if (inet_pton(AF_INET, a.ip, &addr) == 1) ip_a = ntohl(addr.s_addr);
            if (inet_pton(AF_INET, b.ip, &addr) == 1) ip_b = ntohl(addr.s_addr);
            return ip_a < ip_b;
        });

    current_step++;

    {
        char msg[128];
        snprintf(msg, sizeof(msg), "Complete. %d devices found", count);
        ctx.reportProgress(total_steps, total_steps, msg);
    }

    ctx.wsaCleanup();
    return IPD_SUCCESS;
}

void ipd_free_result(ipd_result_t* result) {
    if (!result) return;
    if (result->devices) {
        free(result->devices);
        result->devices = nullptr;
    }
    result->count = 0;
}

void ipd_set_progress_callback(ipd_progress_cb callback) {
    IpdContext::instance().setProgressCallback(callback);
}
