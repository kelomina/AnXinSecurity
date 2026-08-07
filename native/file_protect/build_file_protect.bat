@echo off
REM ============================================================================
REM Build script for AnXinFileProtect.sys (minifilter driver)
REM
REM Prerequisites:
REM   1. Visual Studio 2022 (or newer) with "Desktop development with C++"
REM   2. Windows Driver Kit (WDK) for Windows 10/11
REM
REM Usage:
REM   build_file_protect.bat [Debug|Release]
REM ============================================================================

setlocal enabledelayedexpansion

set CONFIG=%~1
if "%CONFIG%"=="" set CONFIG=Release
set PLATFORM=x64

echo ============================================================================
echo Building AnXinFileProtect minifilter (%CONFIG%^|%PLATFORM%)
echo ============================================================================

REM Find MSBuild
set MSBUILD=
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
    echo [ERROR] MSBuild.exe not found.
    exit /b 1
)

echo [INFO] Using MSBuild: %MSBUILD%

REM Check WDK
if not exist "%ProgramFiles(x86)%\Windows Kits\10\Include\10.0.28000.0\km" (
    echo [WARN] WDK kernel headers not found.
)

cd /d "%~dp0"
%MSBUILD% AnXinFileProtect.vcxproj /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /t:Rebuild

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed with exit code %ERRORLEVEL%.
    exit /b %ERRORLEVEL%
)

echo.
echo ============================================================================
echo Build successful!
echo Output: build\%PLATFORM%\%CONFIG%\AnXinFileProtect.sys
echo INF:    AnXinFileProtect.inf
echo ============================================================================
echo.
echo To install and test:
echo   1. Enable test signing: bcdedit /set testsigning on
echo   2. Restart
echo   3. Create service: sc create AnXinFileProtect type= filesys binPath= "C:\path\to\AnXinFileProtect.sys"
echo   4. Start service:  sc start AnXinFileProtect
echo. 

endlocal
