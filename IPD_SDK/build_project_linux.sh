#!/bin/bash

echo "========================================"
echo "IP Discovery SDK - Linux Build Script"
echo "========================================"
echo

# ================
#      Clear
# ================
echo "[1/3] Cleaning build directory..."
if [ -d "build" ]; then
    rm -rf build
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to delete build directory"
        exit 1
    fi
    echo "[OK] Build directory cleaned"
else
    echo "[INFO] Build directory does not exist, skipping clean"
fi
echo

# ================
#      Configure
# ================
echo "[2/3] Configuring with CMake..."
cmake -B build -G "Unix Makefiles"
if [ $? -ne 0 ]; then
    echo
    echo "[ERROR] CMake configuration failed!"
    echo
    echo "Please check:"
    echo "  1. CMake is installed    (sudo apt install cmake)"
    echo "  2. Build tools installed (sudo apt install build-essential)"
    echo "  3. All libraries exist in 3rdparty/"
    echo
    exit 1
fi
echo "[OK] Configuration successful"
echo

# ================
#      Build
# ================
echo "[3/3] Building project..."
cmake --build build
if [ $? -ne 0 ]; then
    echo
    echo "[ERROR] Build failed!"
    echo "Please check the error messages above."
    echo
    exit 1
fi
echo "[OK] Build successful"
echo

# ================
#      Summary
# ================
echo "========================================"
echo "Build completed successfully!"
echo "========================================"
echo
echo "Output: build/sdk/lib/libIPD_SDK.so"
echo "Header: build/sdk/include/IpDiscoverySdk.h"
echo
echo "[INFO] This is a shared library (.so)."
echo "[INFO] Distribute build/sdk/ to the customer."
echo
