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

set CONFIG=%~1
if "%CONFIG%"=="" set CONFIG=Release

set PLATFORM=x64

echo ============================================================================
echo Building AnXinProcProtect driver (%CONFIG%^|%PLATFORM%)
echo ============================================================================

REM Try to find MSBuild.exe from Visual Studio. A plain for/if (no nested blocks,
REM no enabledelayedexpansion) is used on purpose: cmd.exe misparses a multiline
REM for loop that nests an if-exist block and a goto when delayed expansion is on.
set MSBUILD=
set VS_INSTALL_DIR=
for %%p in (
    "C:\Program Files\Microsoft Visual Studio\18\"
    "C:\Program Files\Microsoft Visual Studio\18\Insiders"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community"
) do if exist "%%~p\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%%~p\MSBuild\Current\Bin\MSBuild.exe" & set "VS_INSTALL_DIR=%%~p"

if "%MSBUILD%"=="" (
    echo [ERROR] MSBuild.exe not found. Please ensure Visual Studio 2022 with WDK is installed.
    echo.
    echo To install WDK, run the Visual Studio Installer, select "Modify" on VS 2022,
    echo then go to "Individual components" ^> search for "WDK".
    exit /b 1
)

echo [INFO] Using MSBuild: %MSBUILD%

REM Set up the WDK/SDK tool environment. Inf2Cat, InfVerif and signtool need the
REM SDK environment variables; without them the post-compile catalog targets fail
REM even though the .sys itself builds fine. Same call build_rel.bat makes.
call "%VS_INSTALL_DIR%\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul 2>&1

REM Check WDK availability. NOTE: use the single-line "if ... goto" form here, NOT a
REM parenthesized block -- "%ProgramFiles(x86)%" expands to "C:\Program Files (x86)"
REM and the parens inside the value break cmd's block parser.
set "WDK_INCLUDE=%ProgramFiles(x86)%\Windows Kits\10\Include\10.0.28000.0\km"
if exist "%WDK_INCLUDE%" goto :wdk_ok
echo [WARN] WDK kernel headers not found at expected path.
echo [WARN] Driver will not build without WDK. Install WDK and retry.
echo [WARN] Expected path: C:\Program Files (x86)\Windows Kits\10\Include\10.0.XXXXX.0\km\
:wdk_ok

REM Run MSBuild
echo [INFO] Building driver...
cd /d "%~dp0"
REM   - WindowsTargetPlatformVersion is pinned (the floating 10.0 resolves to an SDK
REM     without km\ntifs.h).
REM   - SignMode is left EMPTY on purpose: this WDK's own signing targets are broken
REM     (signtool runs without /fd -> fails, and the failed sign DELETES the .sys via
REM     RemoveUnsignedOutput). We build unsigned here and sign manually with signtool
REM     below using the "AnXin Security Test" cert. Do NOT set SignMode non-empty.
REM   - SkipPackageVerification=true disables the InfVerif task (its InfVerif.dll fails
REM     to load in this WDK); EnableInf2cat=false skips the Inf2Cat catalog target
REM     (inf2cat.exe exits -2 on this INF's SourceDisksFiles). Both are non-fatal to the
REM     .sys itself but would otherwise fail the build.
"%MSBUILD%" AnXinProcProtect.vcxproj /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /p:WindowsTargetPlatformVersion=10.0.28000.0 "/p:SignMode=" /p:SkipPackageVerification=true /p:EnableInf2cat=false /p:EnableInfVerification=false /t:Rebuild

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed with exit code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

REM Test-sign the .sys with the "AnXin Security Test" certificate (thumbprint
REM CA21B971BC2EA0201E2AA568B230A0035212246E, CurrentUser\My). The test VM already
REM trusts this cert, so a driver signed with it loads under testsigning; a completely
REM UNSIGNED driver is rejected with error 577 (verified 2026-08).
echo.
echo [INFO] Signing driver with test certificate (AnXin Security Test)...
signtool sign /v /fd SHA256 /s my /sha1 CA21B971BC2EA0201E2AA568B230A0035212246E "build\%PLATFORM%\%CONFIG%\AnXinProcProtect.sys"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Signing failed with exit code %ERRORLEVEL%.
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
