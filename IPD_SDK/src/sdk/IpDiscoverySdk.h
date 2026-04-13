#pragma once

#ifdef _WIN32
  #ifdef IPD_SDK_EXPORTS
    #define IPD_API __declspec(dllexport)
  #else
    #define IPD_API __declspec(dllimport)
  #endif
#else
  #define IPD_API __attribute__((visibility("default")))
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Error codes
// ============================================================
#define IPD_SUCCESS               (0)
#define IPD_ERROR_UNKNOWN        (-1)
#define IPD_ERROR_INVALID_ARGS   (-2)
#define IPD_ERROR_SOCKET         (-3)
#define IPD_ERROR_TIMEOUT        (-4)
#define IPD_ERROR_MEMORY         (-5)
#define IPD_ERROR_CANCELLED      (-6)

// ============================================================
// Device type
// ============================================================
typedef enum {
    IPD_DEVICE_UNKNOWN  = 0,
    IPD_DEVICE_CAMERA   = 1,
    IPD_DEVICE_RADAR    = 2,
    IPD_DEVICE_HOST     = 3,
} ipd_device_type_t;

// ============================================================
// Search flags
// ============================================================
typedef enum {
    IPD_SEARCH_CAMERA  = 0x01,
    IPD_SEARCH_ALL     = 0x01,
} ipd_search_flag_t;

// ============================================================
// Data structures
// ============================================================

typedef struct {
    char              ip[64];
    char              mac[24];
    ipd_device_type_t type;
    char              type_name[32];

    uint16_t          ports[32];
    int               port_count;

    char              name[128];
    char              manufacturer[64];
    char              model[64];
    char              detail[256];
    char              vendor[64];       // MAC 벤더 (OUI 기반)
} ipd_device_t;

typedef struct {
    ipd_device_t* devices;
    int           count;
    char          local_ip[64];
    char          subnet[32];
} ipd_result_t;

typedef struct {
    int         major;
    int         minor;
    int         patch;
    const char* name;
    const char* manufacturer;
} ipd_version_t;

// ============================================================
// Callback
// ============================================================

// 프로그레스 콜백
typedef void (*ipd_progress_cb)(int current, int total, const char* message);

// 비동기 결과 콜백 — ipd_discover_async()에서 사용
typedef void (*ipd_result_cb)(int error_code, const ipd_result_t* result);

// ============================================================
// API
// ============================================================

// SDK 버전 조회
IPD_API void ipd_get_version(ipd_version_t* version);

// 동기 스캔 (기존)
// ports=NULL, port_count=0: 네트워크 스캔만 수행
// ports 배열 지정: 해당 포트들로 TCP probe + 오픈 여부 기록
// subnet=NULL: 자동 감지, subnet 지정: 해당 서브넷 스캔 (예: "192.168.0.0/24")
IPD_API int ipd_discover(ipd_search_flag_t flags, int timeout_ms,
                         const uint16_t* ports, int port_count,
                         const char* subnet, ipd_result_t* result);

// 비동기 스캔 — 별도 스레드에서 실행, 완료 시 callback 호출
IPD_API int ipd_discover_async(ipd_search_flag_t flags, int timeout_ms,
                               const uint16_t* ports, int port_count,
                               const char* subnet, ipd_result_cb callback);

// 특정 IP 재스캔
IPD_API int ipd_rescan_host(const char* ip, const uint16_t* ports, int port_count,
                            int timeout_ms, ipd_device_t* device);

// 스캔 중지
IPD_API void ipd_cancel();

// 검색 결과 메모리 해제
IPD_API void ipd_free_result(ipd_result_t* result);

// 프로그레스 콜백 등록
IPD_API void ipd_set_progress_callback(ipd_progress_cb callback);

#ifdef __cplusplus
} /* extern "C" */
#endif
