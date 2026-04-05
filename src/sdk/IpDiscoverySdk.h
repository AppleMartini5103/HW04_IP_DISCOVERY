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
    IPD_DEVICE_UNKNOWN  = 0,   // 타입 불명 (IP+MAC만 확인됨)
    IPD_DEVICE_IGD      = 1,   // 공유기 (UPnP IGD)
    IPD_DEVICE_CAMERA   = 2,   // IP 카메라 (ONVIF)
    IPD_DEVICE_RADAR    = 3,   // 레이더 (알려진 포트 매칭)
    IPD_DEVICE_HOST     = 4,   // 일반 호스트
} ipd_device_type_t;

// ============================================================
// Search flags
// ============================================================
typedef enum {
    IPD_SEARCH_UPNP    = 0x01,  // UPnP 디바이스 검색
    IPD_SEARCH_CAMERA  = 0x02,  // ONVIF 카메라 검색
    IPD_SEARCH_ALL     = 0x03,  // 전체 검색
} ipd_search_flag_t;

// ============================================================
// Data structures
// ============================================================

// Grid 한 줄 = 디바이스 하나
typedef struct {
    char              ip[64];            // IP 주소
    char              mac[24];           // MAC 주소
    ipd_device_type_t type;              // 디바이스 타입
    char              type_name[32];     // 타입 문자열 ("IGD", "Camera" 등)

    // 열린 포트 목록
    uint16_t          ports[32];
    int               port_count;

    // 상세 정보 (타입에 따라 채워짐)
    char              name[128];         // 디바이스 이름
    char              manufacturer[64];  // 제조사
    char              model[64];         // 모델명
    char              detail[256];       // 추가 정보 (WAN IP 등)
} ipd_device_t;

// 검색 결과
typedef struct {
    ipd_device_t* devices;    // 디바이스 배열 (Grid rows)
    int           count;      // 디바이스 수
    char          local_ip[64];  // 검색에 사용된 로컬 IP
    char          subnet[32];    // 검색 서브넷
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

// SDK 버전 정보 조회
IPD_API void ipd_get_version(ipd_version_t* version);

// 네트워크 디바이스 검색
IPD_API int ipd_discover(ipd_search_flag_t flags, int timeout_ms, ipd_result_t* result);

// 검색 결과 메모리 해제
IPD_API void ipd_free_result(ipd_result_t* result);

// 프로그레스 콜백 등록
IPD_API void ipd_set_progress_callback(ipd_progress_cb callback);

#ifdef __cplusplus
} /* extern "C" */
#endif
