@echo off
REM ============================================================================
REM Build script for AnXinProcProtect.sys
REM
REM Prerequisites:
REM   1. Visual Studio 2022 (or newer) with "Desktop development with C++"
REM   2. Windows Driver Kit (WDK) for Windows 10/11
REM
REM Usage:
REM   build_driver.bat [Debug|Release]
REM
REM Examples:
REM   build_driver.bat Release     - Build production signed driver
REM   build_driver.bat Debug       - Build debug driver with verbose logging
REM ============================================================================

setlocal enabledelayedexpansion

set CONFIG=%~1
if "%CONFIG%"=="" set CONFIG=Release

set PLATFORM=x64

echo ============================================================================
echo Building AnXinProcProtect driver (%CONFIG%^|%PLATFORM%)
echo ============================================================================

REM Try to find MSBuild.exe from Visual Studio 2022
set MSBUILD=
set VS_INSTALL_DIR=

REM Check common VS 2022 paths
for %%p in (
    "C:\Program Files\Microsoft Visual Studio\18\"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community"
) do (
    if exist "%%~p\MSBuild\Current\Bin\MSBuild.exe" (
        set MSBUILD="%%~p\MSBuild\Current\Bin\MSBuild.exe"
        set VS_INSTALL_DIR=%%~p
        goto :found_msbuild
    )
)

REM Try vswhere as fallback
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do (
        if exist "%%i\MSBuild\Current\Bin\MSBuild.exe" (
            set MSBUILD="%%i\MSBuild\Current\Bin\MSBuild.exe"
            set VS_INSTALL_DIR=%%i
            goto :found_msbuild
        )
    )
)

:found_msbuild
if "%MSBUILD%"=="" (
    echo [ERROR] MSBuild.exe not found. Please ensure Visual Studio 2022 with WDK is installed.
    echo.
    echo To install WDK, run the Visual Studio Installer, select "Modify" on VS 2022,
    echo then go to "Individual components" ^> search for "WDK".
    exit /b 1
)

echo [INFO] Using MSBuild: %MSBUILD%

REM Check WDK availability
if not exist "%ProgramFiles(x86)%\Windows Kits\10\Include\10.0.28000.0\km" (
    echo [WARN] WDK kernel headers not found at expected path.
    echo [WARN] Driver will not build without WDK. Install WDK and retry.
    echo [WARN] Expected path: C:\Program Files (x86)\Windows Kits\10\Include\10.0.XXXXX.0\km\
)

REM Run MSBuild
echo [INFO] Building driver...
cd /d "%~dp0"
%MSBUILD% AnXinProcProtect.vcxproj /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /t:Rebuild

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed with exit code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================================
echo Build successful!
echo Output: build\%PLATFORM%\%CONFIG%\AnXinProcProtect.sys
echo INF:    driver.inf
echo ============================================================================
echo.
echo To install and test the driver:
echo   1. Enable test signing: bcdedit /set testsigning on
echo   2. Restart the system
echo   3. Create service: sc create AnXinProcProtect type= kernel binPath= "C:\path\to\AnXinProcProtect.sys"
echo   4. Start service:  sc start AnXinProcProtect
echo   5. Check status:   sc query AnXinProcProtect
echo   6. View logs:      DbgView (Sysinternals)
echo.
echo To uninstall:
echo   sc stop AnXinProcProtect
echo   sc delete AnXinProcProtect
echo.

endlocal
