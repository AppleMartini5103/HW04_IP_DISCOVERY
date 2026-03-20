@echo off

setlocal enabledelayedexpansion

echo ========================================
echo miniupnpc 2.3.3 DLL Build Script
echo (Windows Library Build)
echo ========================================
echo.

echo [0/5] set Parameter
set SOURCE_DIR=miniupnpc-2.3.3
set BUILD_DIR=build_temp
set OUTPUT_INCLUDE=include
set OUTPUT_LIB=lib\window
set GENERATOR_TYPE=NMAKE

if not exist .\miniupnpc-2.3.3.tar.gz (
    echo [ERROR] miniupnpc-2.3.3.tar.gz not found!
    pause
    exit /b 1
)
echo [SUCCESS] set Parameter

echo [1/5] ready for build
:: 소스 압축 해제
tar -xzf .\miniupnpc-2.3.3.tar.gz
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] fail to extract tar.gz!
    pause
    exit /b 1
)

if not exist %BUILD_DIR% mkdir %BUILD_DIR%
if not exist %OUTPUT_INCLUDE% mkdir %OUTPUT_INCLUDE%
if not exist %OUTPUT_LIB% mkdir %OUTPUT_LIB%

echo [SUCCESS] ready for build


echo [2/5] CMake build

set CONFIG_SUCCESS=0

:: cl
where cl >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    echo [INFO] cl detected, using NMake Makefiles...
    cmake -B %BUILD_DIR% -S %SOURCE_DIR% ^
        -G "NMake Makefiles" ^
        -DCMAKE_BUILD_TYPE=Release ^
        -DUPNPC_BUILD_STATIC=OFF ^
        -DUPNPC_BUILD_SHARED=ON ^
        -DUPNPC_BUILD_TESTS=OFF ^
        -DUPNPC_BUILD_SAMPLE=OFF
    if !ERRORLEVEL! EQU 0 set CONFIG_SUCCESS=1
)

:: Visual Studio
if !CONFIG_SUCCESS! EQU 0 (
    echo [INFO] Trying Visual Studio generators...

    if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
    cmake -B %BUILD_DIR% -S %SOURCE_DIR% -G "Visual Studio 17 2022" -A x64 ^
        -DUPNPC_BUILD_STATIC=OFF -DUPNPC_BUILD_SHARED=ON ^
        -DUPNPC_BUILD_TESTS=OFF -DUPNPC_BUILD_SAMPLE=OFF >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        echo [INFO] Using Visual Studio 17 2022
        set CONFIG_SUCCESS=1
        set GENERATOR_TYPE=VS
    )

    if !CONFIG_SUCCESS! EQU 0 (
        if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
        cmake -B %BUILD_DIR% -S %SOURCE_DIR% -G "Visual Studio 16 2019" -A x64 ^
            -DUPNPC_BUILD_STATIC=OFF -DUPNPC_BUILD_SHARED=ON ^
            -DUPNPC_BUILD_TESTS=OFF -DUPNPC_BUILD_SAMPLE=OFF >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            echo [INFO] Using Visual Studio 16 2019
            set CONFIG_SUCCESS=1
            set GENERATOR_TYPE=VS
        )
    )

    if !CONFIG_SUCCESS! EQU 0 (
        if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
        cmake -B %BUILD_DIR% -S %SOURCE_DIR% -G "Visual Studio 15 2017 Win64" ^
            -DUPNPC_BUILD_STATIC=OFF -DUPNPC_BUILD_SHARED=ON ^
            -DUPNPC_BUILD_TESTS=OFF -DUPNPC_BUILD_SAMPLE=OFF >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            echo [INFO] Using Visual Studio 15 2017
            set CONFIG_SUCCESS=1
            set GENERATOR_TYPE=VS
        )
    )
)

:: MinGW
if !CONFIG_SUCCESS! EQU 0 (
    where mingw32-make >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        echo [INFO] Detected MinGW, using MinGW Makefiles...
        cmake -B %BUILD_DIR% -S %SOURCE_DIR% ^
            -G "MinGW Makefiles" ^
            -DCMAKE_BUILD_TYPE=Release ^
            -DUPNPC_BUILD_STATIC=OFF ^
            -DUPNPC_BUILD_SHARED=ON ^
            -DUPNPC_BUILD_TESTS=OFF ^
            -DUPNPC_BUILD_SAMPLE=OFF
        if !ERRORLEVEL! EQU 0 set CONFIG_SUCCESS=1
    )
)

if !CONFIG_SUCCESS! EQU 0 (
    echo [ERROR] No build system found!
    echo Please install one of:
    echo   1. Visual Studio Build Tools ^(Desktop development with C++^)
    echo      https://visualstudio.microsoft.com/downloads/
    echo   2. MinGW-w64: winget install mingw
    echo   3. Run from "Developer Command Prompt for VS"
    pause
    exit /b 1
)

cmake --build %BUILD_DIR% --config Release

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] CMake build failed!
    pause
    exit /b 1
)
echo [SUCCESS] CMake build

echo [3/5] header copy
:: 헤더 복사
if not exist %OUTPUT_INCLUDE% mkdir %OUTPUT_INCLUDE%
copy %SOURCE_DIR%\include\*.h %OUTPUT_INCLUDE%\
echo [SUCCESS] header copy

echo [4/5] binary copy
:: 바이너리 복사
if not exist %OUTPUT_LIB% mkdir %OUTPUT_LIB%

if "%GENERATOR_TYPE%"=="VS" (
    copy %BUILD_DIR%\Release\miniupnpc.dll %OUTPUT_LIB%\
    copy %BUILD_DIR%\Release\miniupnpc.lib %OUTPUT_LIB%\
) else (
    copy %BUILD_DIR%\miniupnpc.dll %OUTPUT_LIB%\
    copy %BUILD_DIR%\miniupnpc.lib %OUTPUT_LIB%\
)

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] binary copy failed!
    pause
    exit /b 1
)
echo [SUCCESS] binary copy

echo [5/5] remove temp build directory
:: 임시 빌드 디렉토리 정리
rmdir /s /q %BUILD_DIR%
rmdir /s /q %SOURCE_DIR%
echo [SUCCESS] remove temp build directory

endlocal