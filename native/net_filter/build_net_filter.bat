@echo off
REM ============================================================================
REM Build script for AnXinNetFilter.sys (WFP callout driver)
REM AnXinNetFilter.sys（WFP Callout 网络过滤驱动）构建脚本
REM
REM Prerequisites / 前置条件:
REM   1. Visual Studio 2022 or newer with "Desktop development with C++"
REM   2. Windows Driver Kit (WDK) matching the installed Windows SDK
REM      本机检查点: %ProgramFiles(x86)%\Windows Kits\10\Include\<ver>\km 必须存在
REM      Checkpoint : the ...\Include\<ver>\km directory must exist
REM
REM Usage / 用法:
REM   build_net_filter.bat [Debug|Release]
REM ============================================================================

setlocal enabledelayedexpansion

set CONFIG=%~1
if "%CONFIG%"=="" set CONFIG=Release
set PLATFORM=x64

echo ============================================================================
echo Building AnXinNetFilter (%CONFIG%^|%PLATFORM%)
echo ============================================================================

REM --- Locate MSBuild ---------------------------------------------------------
set MSBUILD=
for %%p in (
    "C:\Program Files\Microsoft Visual Studio\18"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community"
) do (
    if exist "%%~p\MSBuild\Current\Bin\MSBuild.exe" (
        set MSBUILD="%%~p\MSBuild\Current\Bin\MSBuild.exe"
        goto :found_msbuild
    )
)

if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do (
        if exist "%%i\MSBuild\Current\Bin\MSBuild.exe" (
            set MSBUILD="%%i\MSBuild\Current\Bin\MSBuild.exe"
            goto :found_msbuild
        )
    )
)

:found_msbuild
if "%MSBUILD%"=="" (
    echo [ERROR] MSBuild.exe not found. Install Visual Studio with the C++ workload.
    exit /b 1
)
echo [INFO] Using MSBuild: %MSBUILD%

REM --- Verify the WDK kernel headers are present ------------------------------
REM WFP callout 驱动需要 km\fwpsk.h 与 km\fwpmk.h，仅装 Windows SDK 是不够的。
REM A WFP callout driver needs km\fwpsk.h and km\fwpmk.h; the Windows SDK alone
REM is not enough.
set WDK_FOUND=0
for /d %%k in ("%ProgramFiles(x86)%\Windows Kits\10\Include\*") do (
    if exist "%%~k\km\fwpsk.h" (
        set WDK_FOUND=1
        echo [INFO] WDK kernel headers found: %%~k\km
    )
)
if "%WDK_FOUND%"=="0" (
    echo.
    echo [ERROR] WDK kernel-mode headers not found ^(km\fwpsk.h^).
    echo         This driver cannot be compiled without the WDK.
    echo.
    echo         Install it via the Visual Studio Installer:
    echo           Modify ^> Individual components ^> search "WDK"
    echo         or download "Windows Driver Kit" from
    echo           https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
    echo.
    echo         The WDK version must match the installed Windows SDK version.
    exit /b 1
)

REM --- Build ------------------------------------------------------------------
cd /d "%~dp0"
%MSBUILD% AnXinNetFilter.vcxproj /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /t:Rebuild

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed with exit code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================================
echo Build successful!
echo   Driver: build\%PLATFORM%\%CONFIG%\AnXinNetFilter.sys
echo   INF:    AnXinNetFilter.inf
echo ============================================================================
echo.
echo --- Test-signing and installation (development machines only) ---
echo.
echo 1. Enable test signing, then reboot:
echo      bcdedit /set testsigning on
echo.
echo 2. Create a self-signed test certificate ^(once^):
echo      New-SelfSignedCertificate -Type CodeSigningCert ^
echo        -Subject "CN=AnXin Security Test" -CertStoreLocation Cert:\CurrentUser\My
echo.
echo 3. Sign the driver:
echo      signtool sign /v /fd SHA256 /s My /n "AnXin Security Test" ^
echo        /tr http://timestamp.digicert.com /td SHA256 ^
echo        build\%PLATFORM%\%CONFIG%\AnXinNetFilter.sys
echo.
echo 4. Register and start the kernel service:
echo      sc create AnXinNetFilter type= kernel start= demand ^
echo         binPath= "C:\path\to\AnXinNetFilter.sys"
echo      sc start AnXinNetFilter
echo.
echo 5. Inspect:
echo      sc query AnXinNetFilter
echo      netsh wfp show state file=wfpstate.xml   ^(check the AnXin sublayer^)
echo      DbgView.exe with "Capture Kernel" enabled
echo.
echo 6. Remove:
echo      sc stop AnXinNetFilter
echo      sc delete AnXinNetFilter
echo.
echo Production signing requires an EV code-signing certificate plus Microsoft
echo attestation signing through the Hardware Developer Center.
echo 生产环境签名需要 EV 代码签名证书，并通过微软硬件开发者中心做认证签名。
echo.

endlocal
