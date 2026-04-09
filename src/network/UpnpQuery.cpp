#include "UpnpQuery.h"

#include <miniupnpc.h>
#include <upnpcommands.h>
#include <upnperrors.h>

#include <cstring>

bool upnp_query_igd(int timeout_ms, UpnpIgdInfo& info) {
    info = {};
    info.found = false;

    if (timeout_ms <= 0) timeout_ms = 2000;

    // 1. IGD 검색
    int error = 0;
    struct UPNPDev* devlist = upnpDiscover(
        timeout_ms,     // delay (ms)
        nullptr,        // multicastif
        nullptr,        // minissdpdsock
        UPNP_LOCAL_PORT_ANY,
        0,              // ipv6 = false
        2,              // ttl
        &error
    );

    if (!devlist) {
        return false;
    }

    // 2. 유효한 IGD 선택
    struct UPNPUrls urls;
    struct IGDdatas data;
    char lanaddr[64] = {};
    char wanaddr[64] = {};

    int ret = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));

    if (ret == 0) {
        // IGD를 찾지 못함
        freeUPNPDevlist(devlist);
        return false;
    }

    info.found = true;
    info.local_ip = lanaddr;
    info.gateway_ip = wanaddr;

    // descURL에서 IGD IP 추출 (http://192.168.0.1:xxxx/... 형태)
    if (devlist->descURL) {
        std::string url = devlist->descURL;
        // "http://" 이후 IP 부분 추출
        auto start = url.find("://");
        if (start != std::string::npos) {
            start += 3;
            auto end = url.find_first_of(":/", start);
            if (end != std::string::npos) {
                info.gateway_ip = url.substr(start, end - start);
            }
        }
    }

    // 3. 공인 IP 조회
    char externalIP[64] = {};
    int r = UPNP_GetExternalIPAddress(
        urls.controlURL,
        data.first.servicetype,
        externalIP
    );
    if (r == UPNPCOMMAND_SUCCESS) {
        info.wan_ip = externalIP;
    }

    // 4. 연결 상태 조회
    char status[64] = {};
    unsigned int uptime = 0;
    char lastconnerror[64] = {};
    r = UPNP_GetStatusInfo(
        urls.controlURL,
        data.first.servicetype,
        status,
        &uptime,
        lastconnerror
    );
    if (r == UPNPCOMMAND_SUCCESS) {
        info.status = status;
    }

    // 5. 리소스 정리
    FreeUPNPUrls(&urls);
    freeUPNPDevlist(devlist);

    return true;
}
