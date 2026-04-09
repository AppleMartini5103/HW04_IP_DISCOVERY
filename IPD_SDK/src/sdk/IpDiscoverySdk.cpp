#include "IpDiscoverySdk.h"
#include "info/version.h"
#include "network/ArpScanner.h"
#include "network/PortScanner.h"
#include "network/UpnpQuery.h"
#include "network/OnvifDiscovery.h"
#include "network/DeviceClassifier.h"

#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include <thread>
#include <mutex>

#ifdef _WIN32
#include <winsock2.h>
#endif

static ipd_progress_cb g_progress_cb = nullptr;

#ifdef _WIN32
static bool wsa_init() {
    WSADATA wsa;
    return (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
}
static void wsa_cleanup() {
    WSACleanup();
}
#else
static bool wsa_init() { return true; }
static void wsa_cleanup() {}
#endif

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

    if (!wsa_init()) return IPD_ERROR_SOCKET;

    // ========== 로컬 네트워크 정보 감지 ==========
    LocalNetInfo netInfo;
    if (!arp_get_local_net_info(netInfo)) {
        wsa_cleanup();
        return IPD_ERROR_SOCKET;
    }

    strncpy(result->local_ip, netInfo.ip.c_str(), sizeof(result->local_ip) - 1);

    char subnet_str[32];
    snprintf(subnet_str, sizeof(subnet_str), "%s/%d", netInfo.ip.c_str(), netInfo.prefix_len);
    strncpy(result->subnet, subnet_str, sizeof(result->subnet) - 1);

    // 총 단계 수 계산
    int total_steps = 1;  // ARP
    if (port > 0) total_steps++;
    if (flags & IPD_SEARCH_UPNP) total_steps++;
    if (flags & IPD_SEARCH_CAMERA) total_steps++;
    total_steps++;  // 타입 판별
    int current_step = 0;

    // ========== 1단계: ARP 스캔 ==========
    if (g_progress_cb) {
        char msg[128];
        snprintf(msg, sizeof(msg), "ARP scanning %s/%d ...", netInfo.ip.c_str(), netInfo.prefix_len);
        g_progress_cb(current_step, total_steps, msg);
    }

    std::vector<ArpEntry> arpResults;
    if (!arp_scan_subnet(netInfo, arpResults)) {
        wsa_cleanup();
        return IPD_ERROR_SOCKET;
    }
    current_step++;

    if (arpResults.empty()) {
        if (g_progress_cb) {
            g_progress_cb(total_steps, total_steps, "No hosts found");
        }
        wsa_cleanup();
        return IPD_SUCCESS;
    }

    if (g_progress_cb) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Found %d hosts", static_cast<int>(arpResults.size()));
        g_progress_cb(current_step, total_steps, msg);
    }

    // ========== 결과 구조체 할당 ==========
    int count = static_cast<int>(arpResults.size());
    result->devices = static_cast<ipd_device_t*>(calloc(count, sizeof(ipd_device_t)));
    if (!result->devices) {
        wsa_cleanup();
        return IPD_ERROR_MEMORY;
    }
    result->count = count;

    for (int i = 0; i < count; i++) {
        strncpy(result->devices[i].ip, arpResults[i].ip.c_str(), sizeof(result->devices[i].ip) - 1);
        strncpy(result->devices[i].mac, arpResults[i].mac.c_str(), sizeof(result->devices[i].mac) - 1);
        result->devices[i].type = IPD_DEVICE_UNKNOWN;
        strncpy(result->devices[i].type_name, "Unknown", sizeof(result->devices[i].type_name) - 1);
    }

    // ========== 2단계: TCP 포트 스캔 (port > 0일 때만, 멀티스레드) ==========
    if (port > 0) {
        if (g_progress_cb) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Port scanning %d hosts on port %d...", count, port);
            g_progress_cb(current_step, total_steps, msg);
        }

        int port_timeout = (timeout_ms > 0) ? timeout_ms : 500;

        // 스레드 수 = CPU 코어 수 기반 (최소 2, 최대 32)
        int hw_threads = static_cast<int>(std::thread::hardware_concurrency());
        if (hw_threads < 2) hw_threads = 2;
        if (hw_threads > 32) hw_threads = 32;

        // 배치 단위로 병렬 처리
        for (int batch_start = 0; batch_start < count; batch_start += hw_threads) {
            int batch_end = batch_start + hw_threads;
            if (batch_end > count) batch_end = count;

            std::vector<std::thread> threads;
            for (int i = batch_start; i < batch_end; i++) {
                threads.emplace_back([&result, i, port, port_timeout]() {
                    if (port_check_tcp(result->devices[i].ip, port, port_timeout)) {
                        result->devices[i].ports[0] = port;
                        result->devices[i].port_count = 1;
                    }
                });
            }
            for (auto& th : threads) {
                th.join();
            }
        }
        current_step++;
    }

    // ========== 3단계: 프로토콜별 상세 조회 ==========
    UpnpIgdInfo igdInfo = {};
    std::vector<OnvifDevice> onvifDevices;

    if (flags & IPD_SEARCH_UPNP) {
        if (g_progress_cb) {
            g_progress_cb(current_step, total_steps, "Querying UPnP IGD...");
        }
        upnp_query_igd(timeout_ms > 0 ? timeout_ms : 2000, igdInfo);
        current_step++;
    }

    if (flags & IPD_SEARCH_CAMERA) {
        if (g_progress_cb) {
            g_progress_cb(current_step, total_steps, "Discovering ONVIF cameras...");
        }
        onvif_discover(timeout_ms > 0 ? timeout_ms : 3000, onvifDevices);

        for (size_t i = 0; i < onvifDevices.size(); i++) {
            if (!onvifDevices[i].service_url.empty()) {
                if (g_progress_cb) {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Querying ONVIF camera %s (%d/%d)",
                             onvifDevices[i].ip.c_str(),
                             static_cast<int>(i + 1),
                             static_cast<int>(onvifDevices.size()));
                    g_progress_cb(current_step, total_steps, msg);
                }
                onvif_get_device_info(onvifDevices[i].service_url, onvifDevices[i]);
            }
        }
        current_step++;
    }

    // ========== 4단계: 디바이스 타입 판별 ==========
    if (g_progress_cb) {
        g_progress_cb(current_step, total_steps, "Classifying devices...");
    }

    for (int i = 0; i < count; i++) {
        classify_device(result->devices[i], igdInfo, onvifDevices);
    }
    current_step++;

    if (g_progress_cb) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Complete. %d devices found", count);
        g_progress_cb(total_steps, total_steps, msg);
    }

    wsa_cleanup();
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
    g_progress_cb = callback;
}
