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
typedef void (*ipd_progress_cb)(int current, int total, const char* message);

// ============================================================
// API
// ============================================================

IPD_API void ipd_get_version(ipd_version_t* version);

// port=0: 네트워크 스캔만 수행 (TCP probe → ARP 캐시 → IP+MAC 수집)
// port>0: 해당 포트로 TCP probe + 포트 오픈 여부도 기록
IPD_API int ipd_discover(ipd_search_flag_t flags, int timeout_ms, uint16_t port, ipd_result_t* result);

IPD_API void ipd_free_result(ipd_result_t* result);

IPD_API void ipd_set_progress_callback(ipd_progress_cb callback);

#ifdef __cplusplus
} /* extern "C" */
#endif
