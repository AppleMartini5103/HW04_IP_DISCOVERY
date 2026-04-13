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
#include <atomic>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// ============================================================
// IpdContext — Winsock, 콜백, 취소, 디바이스 판별
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
        if (cb) cb(current, total, message);
    }

    void cancel() { m_cancelled = true; }
    void resetCancel() { m_cancelled = false; }
    bool isCancelled() const { return m_cancelled; }
    std::atomic<bool>& cancelledRef() { return m_cancelled; }

    // async 스레드 관리
    bool startAsync(std::thread&& t) {
        std::lock_guard<std::mutex> lock(m_asyncMutex);
        if (m_asyncRunning) return false;  // 중복 호출 방지
        if (m_asyncThread.joinable()) m_asyncThread.join();
        m_asyncRunning = true;
        m_asyncThread = std::move(t);
        return true;
    }

    void finishAsync() {
        std::lock_guard<std::mutex> lock(m_asyncMutex);
        m_asyncRunning = false;
    }

    bool isAsyncRunning() {
        std::lock_guard<std::mutex> lock(m_asyncMutex);
        return m_asyncRunning;
    }

    void waitAsync() {
        std::lock_guard<std::mutex> lock(m_asyncMutex);
        if (m_asyncThread.joinable()) {
            m_asyncMutex.unlock();
            m_asyncThread.join();
            m_asyncMutex.lock();
            m_asyncRunning = false;
        }
    }

    void classifyDevice(ipd_device_t& device, const std::vector<OnvifDevice>& onvifDevices) {
        std::string deviceIp = device.ip;

        // 1순위: ONVIF Camera
        for (const auto& cam : onvifDevices) {
            if (cam.ip == deviceIp) {
                device.type = IPD_DEVICE_CAMERA;
                strncpy(device.type_name, "Camera", sizeof(device.type_name) - 1);
                strncpy(device.manufacturer, cam.manufacturer.c_str(), sizeof(device.manufacturer) - 1);
                strncpy(device.model, cam.model.c_str(), sizeof(device.model) - 1);
                if (!cam.firmware_version.empty()) {
                    snprintf(device.detail, sizeof(device.detail), "FW:%s", cam.firmware_version.c_str());
                }
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

        // 3순위: Host
        if (device.port_count > 0) {
            device.type = IPD_DEVICE_HOST;
            strncpy(device.type_name, "Host", sizeof(device.type_name) - 1);
            return;
        }

        device.type = IPD_DEVICE_UNKNOWN;
        strncpy(device.type_name, "Unknown", sizeof(device.type_name) - 1);
    }

    ~IpdContext() {
        // 프로세스 종료 시 async 스레드 안전하게 종료
        m_cancelled = true;
        if (m_asyncThread.joinable()) m_asyncThread.join();
    }

private:
    IpdContext() : m_cancelled(false), m_asyncRunning(false) {}
    std::mutex m_mutex;
    ipd_progress_cb m_progressCb = nullptr;
    int m_wsaRefCount = 0;
    std::atomic<bool> m_cancelled;

    // async 관리
    std::mutex m_asyncMutex;
    std::thread m_asyncThread;
    bool m_asyncRunning = false;
};

// ============================================================
// 내부: 동기 스캔 핵심 로직
// ============================================================

static int ipd_discover_internal(ipd_search_flag_t flags, int timeout_ms,
                                  const uint16_t* ports, int port_count,
                                  const char* subnet, ipd_result_t* result) {
    if (!result) return IPD_ERROR_INVALID_ARGS;
    memset(result, 0, sizeof(ipd_result_t));

    auto& ctx = IpdContext::instance();
    ctx.resetCancel();

    if (!ctx.wsaInit()) return IPD_ERROR_SOCKET;

    // ========== 네트워크 정보 ==========
    NetworkScanner scanner;
    LocalNetInfo netInfo;

    if (subnet) {
        if (!scanner.parseSubnet(subnet, netInfo)) {
            ctx.wsaCleanup();
            return IPD_ERROR_INVALID_ARGS;
        }
    } else {
        if (!scanner.getLocalNetInfo(netInfo)) {
            ctx.wsaCleanup();
            return IPD_ERROR_SOCKET;
        }
    }

    strncpy(result->local_ip, netInfo.ip.c_str(), sizeof(result->local_ip) - 1);
    char subnet_str[32];
    snprintf(subnet_str, sizeof(subnet_str), "%s/%d", netInfo.ip.c_str(), netInfo.prefix_len);
    strncpy(result->subnet, subnet_str, sizeof(result->subnet) - 1);

    // 단계 수 계산
    int total_steps = 1;
    if (flags & IPD_SEARCH_CAMERA) total_steps++;
    total_steps++;
    int current_step = 0;

    // ========== 1단계: 네트워크 스캔 ==========
    {
        char msg[128];
        snprintf(msg, sizeof(msg), "Network scanning %s/%d ...", netInfo.ip.c_str(), netInfo.prefix_len);
        ctx.reportProgress(current_step, total_steps, msg);
    }

    std::vector<uint16_t> portVec;
    if (ports && port_count > 0) portVec.assign(ports, ports + port_count);
    std::vector<ScanEntry> scanResults;

    if (!scanner.scan(netInfo, portVec, scanResults, ctx.cancelledRef())) {
        ctx.wsaCleanup();
        return ctx.isCancelled() ? IPD_ERROR_CANCELLED : IPD_ERROR_SOCKET;
    }
    current_step++;

    if (ctx.isCancelled()) { ctx.wsaCleanup(); return IPD_ERROR_CANCELLED; }

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
    if (!result->devices) { ctx.wsaCleanup(); return IPD_ERROR_MEMORY; }
    result->count = count;

    for (int i = 0; i < count; i++) {
        strncpy(result->devices[i].ip, scanResults[i].ip.c_str(), sizeof(result->devices[i].ip) - 1);
        strncpy(result->devices[i].mac, scanResults[i].mac.c_str(), sizeof(result->devices[i].mac) - 1);
        result->devices[i].type = IPD_DEVICE_UNKNOWN;
        strncpy(result->devices[i].type_name, "Unknown", sizeof(result->devices[i].type_name) - 1);

        // MAC 벤더 조회
        std::string vendor = NetworkScanner::lookupVendor(scanResults[i].mac);
        if (!vendor.empty()) {
            strncpy(result->devices[i].vendor, vendor.c_str(), sizeof(result->devices[i].vendor) - 1);
        }

        // 열린 포트 복사
        int pc = 0;
        for (uint16_t p : scanResults[i].open_ports) {
            if (pc >= 32) break;
            result->devices[i].ports[pc++] = p;
        }
        result->devices[i].port_count = pc;
    }

    // ========== 2단계: ONVIF ==========
    std::vector<OnvifDevice> onvifDevices;

    if ((flags & IPD_SEARCH_CAMERA) && !ctx.isCancelled()) {
        ctx.reportProgress(current_step, total_steps, "Discovering ONVIF cameras...");

        OnvifDiscovery onvif;
        int onvif_timeout = (timeout_ms > 2000) ? timeout_ms : 2000;
        onvif.discover(onvif_timeout, onvifDevices);

        if (!onvifDevices.empty() && !ctx.isCancelled()) {
            char msg[128];
            snprintf(msg, sizeof(msg), "Querying %d ONVIF cameras...", static_cast<int>(onvifDevices.size()));
            ctx.reportProgress(current_step, total_steps, msg);

            int camBatch = static_cast<int>(std::thread::hardware_concurrency());
            if (camBatch < 2) camBatch = 2;
            if (camBatch > 8) camBatch = 8;

            int camCount = static_cast<int>(onvifDevices.size());
            for (int bs = 0; bs < camCount; bs += camBatch) {
                int be = bs + camBatch;
                if (be > camCount) be = camCount;

                std::vector<std::thread> cam_threads;
                for (int ci = bs; ci < be; ci++) {
                    if (!onvifDevices[ci].service_url.empty()) {
                        cam_threads.emplace_back([&onvif, &onvifDevices, ci, onvif_timeout]() {
                            onvif.getDeviceInfo(onvifDevices[ci].service_url, onvifDevices[ci], onvif_timeout);
                        });
                    }
                }
                for (auto& th : cam_threads) { th.join(); }
            }
        }
        current_step++;
    }

    if (ctx.isCancelled()) {
        ipd_free_result(result);
        ctx.wsaCleanup();
        return IPD_ERROR_CANCELLED;
    }

    // ========== 3단계: 타입 판별 + 정렬 ==========
    ctx.reportProgress(current_step, total_steps, "Classifying devices...");

    for (int i = 0; i < count; i++) {
        ctx.classifyDevice(result->devices[i], onvifDevices);
    }

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

int ipd_discover(ipd_search_flag_t flags, int timeout_ms,
                 const uint16_t* ports, int port_count,
                 const char* subnet, ipd_result_t* result) {
    return ipd_discover_internal(flags, timeout_ms, ports, port_count, subnet, result);
}

int ipd_discover_async(ipd_search_flag_t flags, int timeout_ms,
                       const uint16_t* ports, int port_count,
                       const char* subnet, ipd_result_cb callback) {
    if (!callback) return IPD_ERROR_INVALID_ARGS;

    auto& ctx = IpdContext::instance();

    // 중복 호출 방지
    if (ctx.isAsyncRunning()) return IPD_ERROR_UNKNOWN;

    // 파라미터 복사 (스레드에 전달)
    std::vector<uint16_t> portsCopy;
    if (ports && port_count > 0) portsCopy.assign(ports, ports + port_count);
    std::string subnetCopy = subnet ? subnet : "";

    std::thread t([flags, timeout_ms, portsCopy, subnetCopy, callback]() {
        auto& ctx = IpdContext::instance();
        ipd_result_t result = {};
        int ret = ipd_discover_internal(
            flags, timeout_ms,
            portsCopy.empty() ? nullptr : portsCopy.data(),
            static_cast<int>(portsCopy.size()),
            subnetCopy.empty() ? nullptr : subnetCopy.c_str(),
            &result
        );
        callback(ret, &result);
        ipd_free_result(&result);
        ctx.finishAsync();
    });

    if (!ctx.startAsync(std::move(t))) {
        return IPD_ERROR_UNKNOWN;  // 이미 실행 중
    }

    return IPD_SUCCESS;
}

int ipd_rescan_host(const char* ip, const uint16_t* ports, int port_count,
                    int timeout_ms, ipd_device_t* device) {
    if (!ip || !device) return IPD_ERROR_INVALID_ARGS;

    auto& ctx = IpdContext::instance();
    if (!ctx.wsaInit()) return IPD_ERROR_SOCKET;

    memset(device, 0, sizeof(ipd_device_t));

    NetworkScanner scanner;
    ScanEntry entry;
    std::vector<uint16_t> portVec;
    if (ports && port_count > 0) portVec.assign(ports, ports + port_count);

    scanner.scanHost(ip, portVec, entry);

    strncpy(device->ip, entry.ip.c_str(), sizeof(device->ip) - 1);
    strncpy(device->mac, entry.mac.c_str(), sizeof(device->mac) - 1);

    // MAC 벤더
    std::string vendor = NetworkScanner::lookupVendor(entry.mac);
    if (!vendor.empty()) {
        strncpy(device->vendor, vendor.c_str(), sizeof(device->vendor) - 1);
    }

    // 포트
    int pc = 0;
    for (uint16_t p : entry.open_ports) {
        if (pc >= 32) break;
        device->ports[pc++] = p;
    }
    device->port_count = pc;

    // ONVIF 조회 (해당 IP에 직접 요청)
    std::vector<OnvifDevice> onvifDevices;
    int onvif_timeout = (timeout_ms > 2000) ? timeout_ms : 2000;

    // 해당 IP의 ONVIF 서비스 URL 추정 후 직접 조회 (여러 경로 시도)
    OnvifDiscovery onvif;
    static const char* ONVIF_PATHS[] = {
        "/onvif/device_service",
        "/onvif/devices",
        "/onvif/services",
    };
    for (const char* path : ONVIF_PATHS) {
        OnvifDevice cam;
        cam.ip = ip;
        char url[256];
        snprintf(url, sizeof(url), "http://%s%s", ip, path);
        cam.service_url = url;
        if (onvif.getDeviceInfo(cam.service_url, cam, onvif_timeout)) {
            onvifDevices.push_back(cam);
            break;
        }
    }

    ctx.classifyDevice(*device, onvifDevices);
    ctx.wsaCleanup();

    return IPD_SUCCESS;
}

void ipd_cancel() {
    IpdContext::instance().cancel();
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
