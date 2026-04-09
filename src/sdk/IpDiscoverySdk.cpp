#include "IpDiscoverySdk.h"
#include "info/version.h"

void ipd_get_version(ipd_version_t* version) {
    if (!version) {
        return;
    }

    version->major = IPD_SDK_VERSION_MAJOR;
    version->minor = IPD_SDK_VERSION_MINOR;
    version->patch = IPD_SDK_VERSION_PATCH;
    version->name = IPD_SDK_NAME;
    version->manufacturer = IPD_SDK_MANUFACTURER;
}
