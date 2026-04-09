#include <cstdio>
#include <chrono>
#include "IpDiscoverySdk.h"

static auto g_start = std::chrono::steady_clock::now();

void progress_callback(int current, int total, const char* message) {
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_start).count();
    printf("[%d/%d] +%5lldms | %s\n", current, total, ms, message);
}

void print_separator() {
    printf("================================================================\n");
}

int main() {
    // ========== SDK 버전 확인 ==========
    ipd_version_t ver = {};
    ipd_get_version(&ver);
    printf("%s v%d.%d.%d (%s)\n", ver.name, ver.major, ver.minor, ver.patch, ver.manufacturer);
    print_separator();

    // ========== 프로그레스 콜백 등록 ==========
    ipd_set_progress_callback(progress_callback);

    // ========== 1단계만 테스트: 네트워크 스캔 (port=0) ==========
    printf("\n[TEST 1] Network scan only (port=0)\n");
    print_separator();

    g_start = std::chrono::steady_clock::now();
    auto t1_start = g_start;

    ipd_result_t result = {};
    int ret = ipd_discover(IPD_SEARCH_ALL, 3000, 0, &result);

    auto t1_end = std::chrono::steady_clock::now();
    auto t1_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1_end - t1_start).count();

    if (ret == IPD_SUCCESS) {
        printf("\nLocal IP : %s\n", result.local_ip);
        printf("Subnet   : %s\n", result.subnet);
        printf("Devices  : %d\n\n", result.count);

        printf("%-4s %-16s %-18s %-8s %-20s %s\n",
               "No.", "IP", "MAC", "Type", "Name", "Detail");
        print_separator();

        for (int i = 0; i < result.count; i++) {
            printf("%-4d %-16s %-18s %-8s %-20s %s\n",
                   i + 1,
                   result.devices[i].ip,
                   result.devices[i].mac,
                   result.devices[i].type_name,
                   result.devices[i].name,
                   result.devices[i].detail);
        }
        ipd_free_result(&result);
    } else {
        printf("ipd_discover failed: %d\n", ret);
    }

    printf("\n[TEST 1] Elapsed: %lld ms\n", t1_ms);

    // ========== 2단계 테스트: 네트워크 스캔 + 포트 스캔 (port=554) ==========
    printf("\n\n[TEST 2] Network scan + Port scan (port=554)\n");
    print_separator();

    g_start = std::chrono::steady_clock::now();
    auto t2_start = g_start;

    ipd_result_t result2 = {};
    ret = ipd_discover(IPD_SEARCH_ALL, 3000, 554, &result2);

    auto t2_end = std::chrono::steady_clock::now();
    auto t2_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2_end - t2_start).count();

    if (ret == IPD_SUCCESS) {
        printf("\nDevices with port 554 open:\n");
        print_separator();

        for (int i = 0; i < result2.count; i++) {
            if (result2.devices[i].port_count > 0) {
                printf("  %s (%s) - port %d open - %s %s\n",
                       result2.devices[i].ip,
                       result2.devices[i].mac,
                       result2.devices[i].ports[0],
                       result2.devices[i].type_name,
                       result2.devices[i].detail);
            }
        }
        ipd_free_result(&result2);
    } else {
        printf("ipd_discover failed: %d\n", ret);
    }

    printf("\n[TEST 2] Elapsed: %lld ms\n", t2_ms);

    // ========== 요약 ==========
    print_separator();
    printf("TEST 1 (Network scan only)       : %lld ms\n", t1_ms);
    printf("TEST 2 (Network scan + port 554) : %lld ms\n", t2_ms);
    print_separator();

    printf("\nDone.\n");
    printf("Press Enter to exit...");
    getchar();
    return 0;
}
