# IP Discovery SDK - 개발 로드맵

## 개요

내부망에 연결된 디바이스(공유기, 카메라, 레이더 등)를 검색하여 IP, MAC, 포트, 타입 정보를 Grid에 표출하는 SDK

### 기술 스택

| 기술 | 용도 | 비고 |
|------|------|------|
| ARP 스캔 | 서브넷 전체 디바이스 IP+MAC 검색 | OS API (추가 라이브러리 없음) |
| 포트 스캔 | 열린 포트로 디바이스 타입 추정 | OS API (TCP connect) |
| UPnP | 공유기 상세 정보 (공인 IP, 상태) | miniupnpc 2.3.3 |
| ONVIF | IP 카메라 검색 및 상세 정보 | WS-Discovery + SOAP |
| XML 파싱 | ONVIF 응답 파싱 | pugixml 1.15 (header-only) |

### 탐색 흐름

```
[검색 버튼 클릭]
     │
     ▼
① ARP 스캔 (서브넷 전체) → IP + MAC 목록
     │
     ▼
② 포트 스캔 (주요 포트) → 열린 포트 목록
     │
     ▼
③ 타입 판별 (포트 조합) → IGD / Camera / Radar / Host
     │
     ▼
④ 상세 조회 (타입별)
     ├─ IGD → UPnP로 공인 IP, 연결 상태
     ├─ Camera → ONVIF로 제조사, 모델
     └─ Radar → 알려진 포트 매칭
     │
     ▼
⑤ Grid에 표출
```

---

## 마일스톤 1: 프로젝트 기반 구축

### #1 프로젝트 디렉토리 구조 및 CMakeLists.txt 구성
- [x] 디렉토리 구조 생성 (src/, 3rdparty/)
- [x] CMakeLists.txt 작성 (크로스 플랫폼, miniupnpc 링크, pugixml header-only 포함)

**프로젝트 구조:**
```
HW04_IP_DISCOVERY/
├── 3rdparty/
│   ├── miniupnp/          # UPnP (DLL + LIB + 헤더)
│   └── pugixml/           # XML 파서 (header-only)
├── src/
│   └── sdk/
│       ├── IpDiscoverySdk.h    # 공개 헤더
│       └── IpDiscoverySdk.cpp  # 구현
├── examples/
│   └── main.cpp                # 사용 예제
├── CMakeLists.txt
├── build_project_window.bat
└── build_project_linux.sh
```

### #2 SDK 공개 헤더 설계 (IpDiscoverySdk.h)
- [x] export 매크로 (IPD_API)
- [x] 에러 코드 정의 (IPD_SUCCESS ~ IPD_ERROR_MEMORY)
- [x] 디바이스 타입 enum (IPD_DEVICE_UNKNOWN ~ IPD_DEVICE_HOST)
- [x] 검색 플래그 enum (IPD_SEARCH_UPNP, IPD_SEARCH_CAMERA, IPD_SEARCH_ALL)
- [x] 데이터 구조체 (ipd_device_t, ipd_result_t, ipd_version_t)
- [x] 콜백 타입 (ipd_progress_cb)
- [x] API 함수 선언 (ipd_get_version, ipd_discover, ipd_free_result, ipd_set_progress_callback)

### #3 Windows/Linux 빌드 스크립트 작성
- [x] build_project_window.bat
- [x] build_project_linux.sh

### #4 SDK 버전 정보 API 구현
- [x] src/sdk/IpDiscoverySdk.cpp 생성
- [x] ipd_get_version() 구현
- [x] 버전 상수 정의 (info/version.h)
- [x] 빌드 확인 (DLL 생성 확인)

---

## 마일스톤 2: 네트워크 탐색 핵심 기능

### #5 Network Scan 구현 (2단계 구조)

**설계:**
```
ipd_discover(flags, timeout_ms, port, &result)
  │
  ▼
1단계: ARP 스캔 (항상 수행)
  → 서브넷 내 살아있는 호스트 IP + MAC 수집
  │
  ▼
2단계: TCP 포트 스캔 (port > 0 일 때만 수행)
  → 1단계에서 발견된 호스트에 대해서만 TCP 연결 시도
  → port == 0 이면 2단계 스킵
```

#### 1단계: ARP 스캔
- [x] Windows: SendARP() 기반 서브넷 스캔 구현
- [ ] Linux: raw socket 기반 ARP 스캔 구현 (나중에)
- [x] 로컬 IP/서브넷 자동 감지
- [x] IP + MAC 주소 수집
- [x] 스캔 대상 IP 범위 계산 (예: 192.168.0.1 ~ 192.168.0.254)

**참고 API:**
```c
// Windows: iphlpapi.h
DWORD SendARP(IPAddr DestIP, IPAddr SrcIP, PULONG pMacAddr, PULONG PhyAddrLen);

// Linux: raw socket (나중에 구현)
socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
```

#### 2단계: TCP 포트 스캔 (조건부)
- [x] TCP connect 방식 포트 스캔
- [x] port == 0 이면 스킵
- [x] 1단계에서 발견된 호스트에 대해서만 수행
- [x] 타임아웃 설정 (non-blocking connect + select)

---

## 마일스톤 3: 프로토콜별 상세 조회

> **구현 순서 변경:** #9 → #10/#11 → #8 순으로 진행
> 이유: 판별 로직(#8)이 프로토콜 응답(#9, #10)에 의존하므로,
> 프로토콜을 먼저 구현한 후 확실한 근거로 판별하는 것이 재작업 없이 효율적

### #9 UPnP IGD 상세 조회 구현
- [x] miniupnpc 래핑
- [x] 구현 항목:

| 함수 | 조회 내용 | 결과 저장 위치 |
|------|----------|--------------|
| upnpDiscover() | IGD 검색 | - |
| UPNP_GetValidIGD() | IGD 연결 | local_ip |
| UPNP_GetExternalIPAddress() | 공인 IP | detail ("WAN:121.x.x.x") |
| UPNP_GetStatusInfo() | 연결 상태 | detail에 추가 |

- [x] 리소스 정리 (FreeUPNPUrls, freeUPNPDevlist)

### #10 ONVIF WS-Discovery 구현
- [x] UDP 멀티캐스트 (239.255.255.250:3702) 전송
- [x] WS-Discovery Probe 메시지 생성 (SOAP XML)
- [x] 응답 수신 및 파싱 (pugixml)
- [x] 카메라 IP + ONVIF 서비스 URL 추출

**WS-Discovery 흐름:**
```
SDK → [Probe 메시지] → 239.255.255.250:3702 (멀티캐스트)
    ← [ProbeMatch 응답] ← 카메라들 응답
```

### #11 ONVIF 디바이스 상세 정보 조회 구현
- [x] GetDeviceInformation SOAP 요청 생성
- [x] HTTP POST로 카메라에 전송
- [x] pugixml XPath로 응답 파싱:

| XPath | 결과 필드 |
|-------|----------|
| `//tds:Manufacturer` | manufacturer |
| `//tds:Model` | model |
| `//tds:FirmwareVersion` | detail에 추가 |

### #8 디바이스 타입 판별 로직 구현
> #9, #10/#11 완료 후 진행 — 프로토콜 응답을 근거로 정확한 판별

- [x] 판별 규칙 정의:

| 조건 | 판별 결과 |
|------|----------|
| UPnP IGD 응답 있음 | IPD_DEVICE_IGD |
| ONVIF 응답 있음 | IPD_DEVICE_CAMERA |
| 5000 open (BSR30 포트) | IPD_DEVICE_RADAR |
| 기타 포트 open | IPD_DEVICE_HOST |
| 포트 없음 | IPD_DEVICE_UNKNOWN |

- [x] type_name 문자열 자동 설정 ("IGD", "Camera", "Radar", "Host")
- [x] 규칙 확장 가능한 구조로 설계

---

## 마일스톤 4: 통합 및 최적화

### #12 ipd_discover() 통합 구현
- [x] 전체 파이프라인 연결:
```
ipd_discover(flags, timeout_ms, port, &result)
  ├─ 1) 로컬 IP/서브넷 감지
  ├─ 2) ARP 스캔 → devices[] 초기 구성
  ├─ 3) 포트 스캔 → ports[] 채움 (port > 0일 때만)
  ├─ 4) 프로토콜 상세 조회 (flags에 따라)
  │     ├─ IPD_SEARCH_UPNP → UPnP 조회
  │     ├─ IPD_SEARCH_CAMERA → ONVIF 조회
  │     └─ IPD_SEARCH_ALL → 둘 다
  └─ 5) 타입 판별 → type, type_name 설정
```
- [x] ipd_free_result() 메모리 해제 구현
- [x] 에러 처리 및 에러 코드 반환

### #13 프로그레스 콜백 구현
- [x] 각 단계별 콜백 호출:

| 단계 | message 예시 |
|------|-------------|
| ARP 스캔 | "ARP scanning 192.168.0.x/24 ..." |
| ARP 완료 | "Found 12 hosts" |
| 포트 스캔 | "Port scanning 12 hosts on port 80..." |
| UPnP 조회 | "Querying UPnP IGD..." |
| ONVIF 검색 | "Discovering ONVIF cameras..." |
| ONVIF 상세 | "Querying ONVIF camera 192.168.0.64 (1/2)" |
| 타입 판별 | "Classifying devices..." |
| 완료 | "Complete. 12 devices found" |

- [x] current/total 값으로 진행률 계산 가능 (동적 total_steps 계산)

### #14 멀티스레드 스캔 최적화
- [x] ARP 스캔 병렬 처리 (최대 64스레드, IP 범위 분배)
- [x] 포트 스캔 병렬 처리 (호스트당 1스레드 동시 스캔)
- [x] std::thread 기반 구현

---

## 마일스톤 5: 테스트 및 문서

### #15 예제 프로그램 작성 (examples/main.cpp)
- [ ] SDK 사용법 데모:
```cpp
#include "IpDiscoverySdk.h"

int main() {
    ipd_version_t ver;
    ipd_get_version(&ver);
    printf("%s v%d.%d.%d\n", ver.name, ver.major, ver.minor, ver.patch);

    ipd_set_progress_callback([](int cur, int total, const char* msg) {
        printf("[%d/%d] %s\n", cur, total, msg);
    });

    ipd_result_t result = {0};
    if (ipd_discover(IPD_SEARCH_ALL, 3000, &result) == IPD_SUCCESS) {
        for (int i = 0; i < result.count; i++) {
            printf("%-16s %-18s %-8s %s\n",
                result.devices[i].ip,
                result.devices[i].mac,
                result.devices[i].type_name,
                result.devices[i].detail);
        }
        ipd_free_result(&result);
    }
    return 0;
}
```

### #16 Windows/Linux 크로스 플랫폼 빌드 검증
- [ ] Windows: Developer Command Prompt → build_project_window.bat 실행
- [ ] Linux: build_project_linux.sh 실행
- [ ] 양쪽 빌드 산출물 확인 (DLL/SO + LIB + 헤더)
- [ ] 예제 프로그램 실행 결과 확인

### #17 SDK 기술 문서 작성
- [ ] BSR30 SDK 기술 문서 형식 참고
- [ ] 문서 항목:

| 섹션 | 내용 |
|------|------|
| 개요 | SDK 목적 및 기능 |
| 시스템 요구사항 | OS, 컴파일러, CMake 버전 |
| 빌드 방법 | Windows/Linux 빌드 절차 |
| API 레퍼런스 | 함수별 파라미터, 반환값, 예제 |
| 데이터 구조체 | 구조체/enum 필드 설명 |
| 에러 코드 | 에러 코드 표 |
| 사용 예제 | 기존 앱에 통합하는 방법 |

---

## 진행 상태 요약

| 마일스톤 | 이슈 | 상태 |
|---------|------|------|
| 1. 프로젝트 기반 | #1 디렉토리 + CMake | ✅ 완료 |
| | #2 공개 헤더 설계 | ✅ 완료 |
| | #3 빌드 스크립트 | ✅ 완료 |
| | #4 버전 API 구현 | ✅ 완료 |
| 2. 네트워크 탐색 | #5 Network Scan (ARP + 포트스캔 2단계) | ✅ 완료 |
| 3. 프로토콜 상세 | #9 UPnP 조회 | ✅ 완료 |
| (순서: #9→#10/#11→#8) | #10 ONVIF 검색 | ✅ 완료 |
| | #11 ONVIF 상세 | ✅ 완료 |
| | #8 타입 판별 | ✅ 완료 |
| 4. 통합/최적화 | #12 통합 구현 | ✅ 완료 |
| | #13 프로그레스 콜백 | ✅ 완료 |
| | #14 멀티스레드 | ✅ 완료 |
| 5. 테스트/문서 | #15 예제 프로그램 | ⬜ 미착수 |
| | #16 빌드 검증 | ⬜ 미착수 |
| | #17 기술 문서 | ⬜ 미착수 |
