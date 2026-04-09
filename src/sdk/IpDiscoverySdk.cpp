#include "IpDiscoverySdk.h"
#include "info/version.h"
#include "network/ArpScanner.h"
#include "network/PortScanner.h"

#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#endif

// 프로그레스 콜백 (전역)
static ipd_progress_cb g_progress_cb = nullptr;

// Winsock 초기화/정리
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
    if (!version) {
        return;
    }

    version->major = IPD_SDK_VERSION_MAJOR;
    version->minor = IPD_SDK_VERSION_MINOR;
    version->patch = IPD_SDK_VERSION_PATCH;
    version->name = IPD_SDK_NAME;
    version->manufacturer = IPD_SDK_MANUFACTURER;
}

int ipd_discover(ipd_search_flag_t flags, int timeout_ms, uint16_t port, ipd_result_t* result) {
    if (!result) {
        return IPD_ERROR_INVALID_ARGS;
    }

    memset(result, 0, sizeof(ipd_result_t));

    if (!wsa_init()) {
        return IPD_ERROR_SOCKET;
    }

    // ========== 로컬 네트워크 정보 감지 ==========
    LocalNetInfo netInfo;
    if (!arp_get_local_net_info(netInfo)) {
        wsa_cleanup();
        return IPD_ERROR_SOCKET;
    }

    strncpy(result->local_ip, netInfo.ip.c_str(), sizeof(result->local_ip) - 1);

    char subnet_str[32];
    snprintf(subnet_str, sizeof(subnet_str), "%s/%d",
             netInfo.ip.c_str(), netInfo.prefix_len);
    strncpy(result->subnet, subnet_str, sizeof(result->subnet) - 1);

    // ========== 1단계: ARP 스캔 ==========
    if (g_progress_cb) {
        g_progress_cb(0, 1, "ARP scanning...");
    }

    std::vector<ArpEntry> arpResults;
    if (!arp_scan_subnet(netInfo, arpResults)) {
        wsa_cleanup();
        return IPD_ERROR_SOCKET;
    }

    if (arpResults.empty()) {
        wsa_cleanup();
        return IPD_SUCCESS;  // 발견된 호스트 없음
    }

    if (g_progress_cb) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Found %d hosts", static_cast<int>(arpResults.size()));
        g_progress_cb(1, 1, msg);
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

    // ========== 2단계: TCP 포트 스캔 (port > 0일 때만) ==========
    if (port > 0) {
        int port_timeout = (timeout_ms > 0) ? timeout_ms : 500;

        for (int i = 0; i < count; i++) {
            if (g_progress_cb) {
                char msg[128];
                snprintf(msg, sizeof(msg), "Port scanning %s:%d (%d/%d)",
                         result->devices[i].ip, port, i + 1, count);
                g_progress_cb(i, count, msg);
            }

            if (port_check_tcp(result->devices[i].ip, port, port_timeout)) {
                result->devices[i].ports[0] = port;
                result->devices[i].port_count = 1;
                result->devices[i].type = IPD_DEVICE_HOST;
                strncpy(result->devices[i].type_name, "Host", sizeof(result->devices[i].type_name) - 1);
            }
        }

        if (g_progress_cb) {
            g_progress_cb(count, count, "Port scan complete");
        }
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
