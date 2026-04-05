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

// ============================================================
// Device type
// ============================================================
typedef enum {
    IPD_DEVICE_UNKNOWN  = 0,
    IPD_DEVICE_IGD      = 1,
    IPD_DEVICE_CAMERA   = 2,
    IPD_DEVICE_RADAR    = 3,
    IPD_DEVICE_HOST     = 4,
} ipd_device_type_t;

// ============================================================
// Search flags
// ============================================================
typedef enum {
    IPD_SEARCH_UPNP    = 0x01,
    IPD_SEARCH_CAMERA  = 0x02,
    IPD_SEARCH_ALL     = 0x03,
} ipd_search_flag_t;

// ============================================================
// Data structures
// ============================================================

// Grid 한 줄 = 디바이스 하나
typedef struct {
    char              ip[64];
    char              mac[24];
    ipd_device_type_t type;
    char              type_name[32];

    // 열린 포트 목록
    uint16_t          ports[32];
    int               port_count;

    // 상세 정보
    char              name[128];
    char              manufacturer[64];
    char              model[64];
    char              detail[256];
} ipd_device_t;

// 검색 결과
typedef struct {
    ipd_device_t* devices;
    int           count;
    char          local_ip[64];
    char          subnet[32];
} ipd_result_t;

// SDK 버전 정보
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
typedef void (*ipd_progress_cb)(int current, int total, const char* message);

// ============================================================
// API
// ============================================================

IPD_API void ipd_get_version(ipd_version_t* version);

IPD_API int ipd_discover(ipd_search_flag_t flags, int timeout_ms, ipd_result_t* result);

IPD_API void ipd_free_result(ipd_result_t* result);

IPD_API void ipd_set_progress_callback(ipd_progress_cb callback);

#ifdef __cplusplus
} /* extern "C" */
#endif
