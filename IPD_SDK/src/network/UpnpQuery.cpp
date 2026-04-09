#include "UpnpQuery.h"

#include <miniupnpc.h>
#include <upnpcommands.h>
#include <upnperrors.h>

#include <cstring>

bool upnp_query_igd(int timeout_ms, UpnpIgdInfo& info) {
    info = {};
    info.found = false;

    if (timeout_ms <= 0) timeout_ms = 2000;

    int error = 0;
    struct UPNPDev* devlist = upnpDiscover(
        timeout_ms, nullptr, nullptr,
        UPNP_LOCAL_PORT_ANY, 0, 2, &error
    );

    if (!devlist) return false;

    struct UPNPUrls urls;
    struct IGDdatas data;
    char lanaddr[64] = {};
    char wanaddr[64] = {};

    int ret = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));

    if (ret == 0) {
        freeUPNPDevlist(devlist);
        return false;
    }

    info.found = true;
    info.local_ip = lanaddr;
    info.gateway_ip = wanaddr;

    if (devlist->descURL) {
        std::string url = devlist->descURL;
        auto start = url.find("://");
        if (start != std::string::npos) {
            start += 3;
            auto end = url.find_first_of(":/", start);
            if (end != std::string::npos) {
                info.gateway_ip = url.substr(start, end - start);
            }
        }
    }

    char externalIP[64] = {};
    int r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIP);
    if (r == UPNPCOMMAND_SUCCESS) {
        info.wan_ip = externalIP;
    }

    char status[64] = {};
    unsigned int uptime = 0;
    char lastconnerror[64] = {};
    r = UPNP_GetStatusInfo(urls.controlURL, data.first.servicetype, status, &uptime, lastconnerror);
    if (r == UPNPCOMMAND_SUCCESS) {
        info.status = status;
    }

    FreeUPNPUrls(&urls);
    freeUPNPDevlist(devlist);

    return true;
}
