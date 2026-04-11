CMAKE_MINIMUM_REQUIRED(VERSION 3.15)

IF(POLICY CMP0091)
    CMAKE_POLICY(SET CMP0091 NEW)
ENDIF()

PROJECT(IPD_SDK)

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)
SET(CMAKE_BUILD_TYPE Release)

# Build date (YYYYMMDD)
STRING(TIMESTAMP BUILD_DATE "%Y%m%d")
ADD_COMPILE_DEFINITIONS(IPD_SDK_VERSION_DATE="${BUILD_DATE}")
MESSAGE(STATUS "Build date: ${BUILD_DATE}")

IF(MSVC)
    ADD_COMPILE_OPTIONS(/utf-8)
    MESSAGE(STATUS "MSVC: UTF-8 encoding enabled")

    SET(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    MESSAGE(STATUS "MSVC: Runtime library set to /MD (MultiThreadedDLL) for MFC compatibility")
ENDIF()

MESSAGE(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "Project: ${PROJECT_NAME}")

IF(WIN32 AND NOT DEFINED CMAKE_GENERATOR_PLATFORM)
    SET(CMAKE_GENERATOR_PLATFORM x64)
ENDIF()

# 3rdparty (miniupnp)
SET(MINIUPNP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/miniupnp)
SET(MINIUPNP_INCLUDE_DIR ${MINIUPNP_DIR}/include)
IF(WIN32)
    SET(MINIUPNP_LIB_DIR ${MINIUPNP_DIR}/lib/window)
ELSE()
ENDIF()

# 3rdparty (pugixml)
SET(PUGIXML_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/pugixml)
SET(PUGIXML_INCLUDE_DIR ${PUGIXML_DIR})

# SOURCE
SET(SOURCES
        src/sdk/IpDiscoverySdk.cpp
        src/network/NetworkScanner.cpp
        src/network/OnvifDiscovery.cpp
)

# SHARED LIBRARY
ADD_LIBRARY(${PROJECT_NAME} SHARED ${SOURCES})

# Windows DLL export definition
TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PRIVATE IPD_SDK_EXPORTS)

# SDK output directory
SET(SDK_DIR ${CMAKE_BINARY_DIR}/sdk)

IF(WIN32)
    SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${SDK_DIR}/bin"   # .dll
        ARCHIVE_OUTPUT_DIRECTORY "${SDK_DIR}/lib"   # .lib
    )
ENDIF()

MESSAGE(STATUS "SDK output directory: ${SDK_DIR}")

# INCLUDE
TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PRIVATE
        src
        src/sdk
        src/network
        ${MINIUPNP_INCLUDE_DIR}
        ${PUGIXML_INCLUDE_DIR}
)

# LINK
IF(WIN32)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} PRIVATE
        # 3rdparty (miniupnpc)
        ${MINIUPNP_LIB_DIR}/miniupnpc.lib
        # windows
        ws2_32.lib
        iphlpapi.lib
    )

    # POST BUILD - miniupnpc.dll copy
    ADD_CUSTOM_COMMAND(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${MINIUPNP_LIB_DIR}/miniupnpc.dll"
        $<TARGET_FILE_DIR:${PROJECT_NAME}>
        COMMENT "copying miniupnpc.dll to output directory"
    )
ENDIF()

# SDK header copy
ADD_CUSTOM_COMMAND(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${SDK_DIR}/include"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/src/sdk/IpDiscoverySdk.h"
        "${SDK_DIR}/include/IpDiscoverySdk.h"
    COMMENT "SDK: copying header to sdk/include/"
)
