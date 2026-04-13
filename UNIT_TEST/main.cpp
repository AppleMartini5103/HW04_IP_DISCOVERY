#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>
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

void print_device(int no, const ipd_device_t& d) {
    printf("%-4d %-16s %-18s %-8s %-16s %-20s %s",
           no, d.ip, d.mac, d.type_name, d.vendor, d.name, d.detail);
    if (d.port_count > 0) {
        printf("  ports:");
        for (int j = 0; j < d.port_count; j++) printf(" %d", d.ports[j]);
    }
    printf("\n");
}

int main() {
    // ========== SDK 버전 확인 ==========
    ipd_version_t ver = {};
    ipd_get_version(&ver);
    printf("%s v%d.%d.%d (%s)\n", ver.name, ver.major, ver.minor, ver.patch, ver.manufacturer);
    print_separator();

    ipd_set_progress_callback(progress_callback);

    // ========== TEST 1: 네트워크 스캔만 (포트 없음) ==========
    printf("\n[TEST 1] Network scan only (no ports)\n");
    print_separator();

    g_start = std::chrono::steady_clock::now();
    auto t1_start = g_start;

    ipd_result_t result = {};
    int ret = ipd_discover(IPD_SEARCH_ALL, 3000, NULL, 0, NULL, &result);

    auto t1_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t1_start).count();

    if (ret == IPD_SUCCESS) {
        printf("\nLocal IP : %s\n", result.local_ip);
        printf("Subnet   : %s\n", result.subnet);
        printf("Devices  : %d\n\n", result.count);

        printf("%-4s %-16s %-18s %-8s %-16s %-20s %s\n",
               "No.", "IP", "MAC", "Type", "Vendor", "Name", "Detail");
        print_separator();

        for (int i = 0; i < result.count; i++) {
            print_device(i + 1, result.devices[i]);
        }
        ipd_free_result(&result);
    } else {
        printf("ipd_discover failed: %d\n", ret);
    }
    printf("\n[TEST 1] Elapsed: %lld ms\n", t1_ms);

    // ========== TEST 2: 다중 포트 스캔 (554 + 5000) ==========
    printf("\n\n[TEST 2] Multi-port scan (554, 5000)\n");
    print_separator();

    g_start = std::chrono::steady_clock::now();
    auto t2_start = g_start;

    uint16_t ports[] = {554, 5000};
    ipd_result_t result2 = {};
    ret = ipd_discover(IPD_SEARCH_ALL, 3000, ports, 2, NULL, &result2);

    auto t2_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t2_start).count();

    if (ret == IPD_SUCCESS) {
        printf("\nDevices with open ports:\n");
        print_separator();
        for (int i = 0; i < result2.count; i++) {
            if (result2.devices[i].port_count > 0) {
                print_device(i + 1, result2.devices[i]);
            }
        }
        ipd_free_result(&result2);
    } else {
        printf("ipd_discover failed: %d\n", ret);
    }
    printf("\n[TEST 2] Elapsed: %lld ms\n", t2_ms);

    // ========== TEST 3: 특정 IP 재스캔 (ipd_rescan_host) ==========
    printf("\n\n[TEST 3] Rescan single host (192.168.1.1)\n");
    print_separator();

    g_start = std::chrono::steady_clock::now();
    auto t3_start = g_start;

    ipd_device_t device = {};
    uint16_t rescan_ports[] = {80, 554};
    ret = ipd_rescan_host("192.168.1.1", rescan_ports, 2, 3000, &device);

    auto t3_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t3_start).count();

    if (ret == IPD_SUCCESS) {
        printf("\n");
        printf("%-4s %-16s %-18s %-8s %-16s %-20s %s\n",
               "No.", "IP", "MAC", "Type", "Vendor", "Name", "Detail");
        print_separator();
        print_device(1, device);
    } else {
        printf("ipd_rescan_host failed: %d\n", ret);
    }
    printf("\n[TEST 3] Elapsed: %lld ms\n", t3_ms);

    // ========== TEST 4: 비동기 스캔 (ipd_discover_async) ==========
    printf("\n\n[TEST 4] Async scan + cancel after 2 seconds\n");
    print_separator();

    g_start = std::chrono::steady_clock::now();
    auto t4_start = g_start;

    static std::atomic<bool> async_done(false);
    static int async_ret = 0;
    static int async_count = 0;
    long long t4_ms = 0;

    ret = ipd_discover_async(IPD_SEARCH_ALL, 3000, NULL, 0, NULL,
        [](int error_code, const ipd_result_t* res) {
            async_ret = error_code;
            async_count = res ? res->count : 0;
            async_done = true;
        });

    if (ret == IPD_SUCCESS) {
        printf("Async scan started. Waiting 2 seconds then cancelling...\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));

        if (!async_done) {
            printf("Calling ipd_cancel()...\n");
            ipd_cancel();
        }

        // 완료 대기 (최대 10초)
        int wait = 0;
        while (!async_done && wait < 100) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            wait++;
        }

        t4_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t4_start).count();

        if (async_done) {
            if (async_ret == IPD_ERROR_CANCELLED) {
                printf("Async scan cancelled successfully.\n");
            } else if (async_ret == IPD_SUCCESS) {
                printf("Async scan completed before cancel. Found %d devices.\n", async_count);
            } else {
                printf("Async scan error: %d\n", async_ret);
            }
        } else {
            printf("Async scan timeout (not completed).\n");
        }
        printf("\n[TEST 4] Elapsed: %lld ms\n", t4_ms);
    } else {
        printf("ipd_discover_async failed to start: %d\n", ret);
    }

    // ========== TEST 5: 서브넷 수동 지정 ==========
    printf("\n\n[TEST 5] Manual subnet (192.168.1.0/24)\n");
    print_separator();

    // async가 끝날 때까지 잠시 대기
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    g_start = std::chrono::steady_clock::now();
    auto t5_start = g_start;

    ipd_result_t result5 = {};
    ret = ipd_discover(IPD_SEARCH_ALL, 3000, NULL, 0, "192.168.1.0/24", &result5);

    auto t5_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t5_start).count();

    if (ret == IPD_SUCCESS) {
        printf("\nSubnet   : %s\n", result5.subnet);
        printf("Devices  : %d\n", result5.count);
        ipd_free_result(&result5);
    } else {
        printf("ipd_discover (manual subnet) failed: %d\n", ret);
    }
    printf("\n[TEST 5] Elapsed: %lld ms\n", t5_ms);

    // ========== 요약 ==========
    printf("\n");
    print_separator();
    printf("TEST 1 (Network scan only)          : %lld ms\n", t1_ms);
    printf("TEST 2 (Multi-port 554, 5000)       : %lld ms\n", t2_ms);
    printf("TEST 3 (Rescan host 192.168.1.1)    : %lld ms\n", t3_ms);
    printf("TEST 4 (Async + cancel)             : %lld ms\n", t4_ms);
    printf("TEST 5 (Manual subnet)              : %lld ms\n", t5_ms);
    print_separator();

    printf("\nDone.\n");
    printf("Press Enter to exit...");
    getchar();
    return 0;
}
