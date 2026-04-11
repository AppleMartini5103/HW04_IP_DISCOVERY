@echo off
setlocal

echo ========================================
echo IP Discovery SDK - Windows Build Script
echo ========================================
echo.

REM ================
REM      Clear
REM ================
echo [1/3] Cleaning build directory...
if exist build (
    rmdir /s /q build
    if errorlevel 1 (
        echo [ERROR] Failed to delete build directory
        pause
        exit /b 1
    )
    echo [OK] Build directory cleaned
) else (
    echo [INFO] Build directory does not exist, skipping clean
)
echo.

REM ================
REM      Configure
REM ================
echo [2/3] Configuring with CMake...
cmake -B build -G "Visual Studio 16 2019" -A x64
if errorlevel 1 (
    echo.
    echo [ERROR] CMake configuration failed!
    echo.
    echo Please check:
    echo   1. CMake is installed and in PATH
    echo   2. You are running from "Developer Command Prompt for VS"
    echo   3. All required libraries are in 3rdparty/
    echo.
    pause
    exit /b 1
)
echo [OK] Configuration successful
echo.

REM ================
REM      Build
REM ================
echo [3/3] Building project...
cmake --build build --config Release
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed!
    echo.
    echo Please check the error messages above.
    echo.
    pause
    exit /b 1
)
echo [OK] Build successful
echo.

REM ================
REM      Summary
REM ================
echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Output: build\sdk\bin\Release\IPD_SDK.dll
echo Import: build\sdk\lib\Release\IPD_SDK.lib
echo Header: build\sdk\include\IpDiscoverySdk.h
echo.
echo [INFO] This is a shared library (DLL).
echo [INFO] Link IPD_SDK.lib and distribute IPD_SDK.dll with your application.
echo.
