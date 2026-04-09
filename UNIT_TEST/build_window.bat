@echo off
setlocal

echo ========================================
echo IP Discovery SDK - Unit Test Build
echo ========================================
echo.

REM SDK 먼저 빌드 확인
if not exist "..\IPD_SDK\build\sdk\lib\Release\IPD_SDK.lib" (
    echo [INFO] SDK not built yet. Building SDK first...
    pushd ..\IPD_SDK
    call build_project_window.bat
    popd
    echo.
)

REM ================
REM      Clear
REM ================
echo [1/3] Cleaning build directory...
if exist build (
    rmdir /s /q build
)
echo [OK] Build directory cleaned
echo.

REM ================
REM      Configure
REM ================
echo [2/3] Configuring with CMake...
cmake -B build -G "Visual Studio 16 2019" -A x64
if errorlevel 1 (
    echo [ERROR] CMake configuration failed!
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
    echo [ERROR] Build failed!
    pause
    exit /b 1
)
echo [OK] Build successful
echo.

REM ================
REM      Run
REM ================
echo ========================================
echo Running unit test...
echo ========================================
echo.
build\Release\IPD_UNIT_TEST.exe
echo.
