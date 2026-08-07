@echo off
REM AnXinHypervisor - Build, Sign & Deploy Script
REM Requires: WDK 10.0.26100+, Visual Studio 2022 Build Tools, MASM (ml64)
REM
REM Usage:
REM   build_hypervisor.bat                    Build Release x64 + test sign
REM   build_hypervisor.bat Debug              Build Debug x64 + test sign
REM   build_hypervisor.bat Release sign       Build + sign with production EV cert
REM   build_hypervisor.bat Release cert       Create test certificate only
REM   build_hypervisor.bat Release deploy     Build + sign + install to system
REM   build_hypervisor.bat Release uninstall  Remove driver service

setlocal enabledelayedexpansion

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release

set ACTION=%2
if "%ACTION%"=="" set ACTION=build

set PLATFORM=x64
set DRIVER_NAME=AnXinHypervisor
set DRIVER_FILE=%DRIVER_NAME%.sys
set SERVICE_NAME=AnXinHypervisor
set TEST_CERT_NAME=AnXin Security Test
set TEST_CERT_FILE=AnXinTest.cer
set EV_CERT_SUBJECT=AnXin Security Co., Ltd

echo ============================================
echo  AnXinHypervisor Build System
echo  Config: %CONFIG% / %PLATFORM%
echo  Action: %ACTION%
echo ============================================
echo.

REM ─── Action: Create test certificate ───────────────────────────────
if "%ACTION%"=="cert" goto :create_test_cert

REM ─── Action: Uninstall driver ──────────────────────────────────────
if "%ACTION%"=="uninstall" goto :uninstall_driver

REM ─── Locate WDK ────────────────────────────────────────────────────
set WDK_ROOT=C:\Program Files (x86)\Windows Kits\10
if not exist "%WDK_ROOT%" (
    echo [ERROR] WDK not found at: %WDK_ROOT%
    echo Please install Windows Driver Kit 10.0.26100+
    exit /b 1
)

REM ─── Locate Visual Studio 2022 ─────────────────────────────────────
set VS_PATH=C:\Program Files\Microsoft Visual Studio\2022
if exist "%VS_PATH%\Enterprise" (
    set VS_EDITION=Enterprise
) else if exist "%VS_PATH%\Professional" (
    set VS_EDITION=Professional
) else if exist "%VS_PATH%\Community" (
    set VS_EDITION=Community
) else if exist "%VS_PATH%\BuildTools" (
    set VS_EDITION=BuildTools
) else (
    echo [ERROR] Visual Studio 2022 not found
    exit /b 1
)

echo [INFO] VS Edition: %VS_EDITION%
echo [INFO] WDK Root: %WDK_ROOT%

REM ─── Set up build environment ──────────────────────────────────────
call "%VS_PATH%\%VS_EDITION%\VC\Auxiliary\Build\vcvarsall.bat" %PLATFORM% >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to set up VC environment
    exit /b 1
)

REM ─── Build ─────────────────────────────────────────────────────────
set PROJECT_FILE=%DRIVER_NAME%.vcxproj
if not exist "%~dp0%PROJECT_FILE%" (
    echo [ERROR] Project file not found: %PROJECT_FILE%
    echo Please generate the WDK project first.
    echo Required settings:
    echo   - TargetExtension: .sys
    echo   - DriverType: WDM
    echo   - /kernel /GS- /Oi
    echo   - MASM enabled (ml64)
    echo   - No CRT linkage
    echo   - Entry: DriverEntry
    echo   - Link: ntstrsafe.lib
    exit /b 1
)

echo [BUILD] Compiling %DRIVER_FILE% (%CONFIG%)...
msbuild "%~dp0%PROJECT_FILE%" /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /m /nologo /v:minimal
if errorlevel 1 (
    echo [ERROR] Build failed
    exit /b 1
)

set OUTPUT_PATH=%~dp0%PLATFORM%\%CONFIG%\%DRIVER_FILE%
if not exist "%OUTPUT_PATH%" (
    echo [ERROR] Expected output not found: %OUTPUT_PATH%
    exit /b 1
)

echo.
echo [BUILD] SUCCEEDED: %OUTPUT_PATH%
for %%F in ("%OUTPUT_PATH%") do echo [BUILD] Size: %%~zF bytes
echo.

REM ─── Sign ──────────────────────────────────────────────────────────
if "%ACTION%"=="sign" goto :sign_production
goto :sign_test

REM ─── Test Signing ──────────────────────────────────────────────────
:sign_test
echo [SIGN] Test signing mode...

REM Check if test certificate exists
certutil -store My "%TEST_CERT_NAME%" >nul 2>&1
if errorlevel 1 (
    echo [SIGN] Test certificate not found, creating...
    call :create_test_cert
    if errorlevel 1 exit /b 1
)

signtool sign /v /s My /n "%TEST_CERT_NAME%" /fd sha256 "%OUTPUT_PATH%"
if errorlevel 1 (
    echo [WARN] Test signing failed.
    echo        Ensure test signing mode is enabled:
    echo          bcdedit /set testsigning on
    echo        Then reboot and retry.
    exit /b 1
)

echo [SIGN] Test signed successfully (SHA-256)
echo.
echo [INFO] To load this driver, test signing must be enabled:
echo        bcdedit /set testsigning on
echo        (reboot required)
echo.
goto :post_sign

REM ─── Production Signing ────────────────────────────────────────────
:sign_production
echo [SIGN] Production signing mode (EV certificate)...
echo [INFO] This requires:
echo        1. EV code signing certificate (hardware token or Azure)
echo        2. Microsoft attestation signing via Partner Center
echo.

REM Step 1: Sign with EV cert
signtool sign /v /s My /n "%EV_CERT_SUBJECT%" /fd sha256 /tr http://timestamp.digicert.com /td sha256 "%OUTPUT_PATH%"
if errorlevel 1 (
    echo [ERROR] EV signing failed. Check certificate store.
    echo        Expected subject: %EV_CERT_SUBJECT%
    exit /b 1
)
echo [SIGN] EV signed successfully

REM Step 2: Submit for Microsoft attestation (manual step)
echo.
echo [INFO] Next step: Submit to Microsoft Partner Center for attestation signing
echo        https://partner.microsoft.com/dashboard/hardware/driver/New
echo        Upload: %OUTPUT_PATH%
echo        The attestation-signed driver will work on all Windows 10/11 x64
echo        without requiring test signing mode.
echo.
goto :post_sign

REM ─── Post-sign actions ─────────────────────────────────────────────
:post_sign

REM Verify signature
echo [VERIFY] Checking signature...
signtool verify /v /kp "%OUTPUT_PATH%" 2>nul
if errorlevel 1 (
    echo [WARN] Signature verification failed (expected in test mode without root cert)
) else (
    echo [VERIFY] Signature valid
)

if "%ACTION%"=="deploy" goto :deploy_driver
goto :done

REM ─── Deploy (install driver service) ───────────────────────────────
:deploy_driver
echo.
echo [DEPLOY] Installing %SERVICE_NAME% service...

set DEST=%SystemRoot%\System32\drivers\%DRIVER_FILE%
copy /Y "%OUTPUT_PATH%" "%DEST%"
if errorlevel 1 (
    echo [ERROR] Failed to copy driver to %DEST%
    echo        Run as Administrator.
    exit /b 1
)
echo [DEPLOY] Copied to %DEST%

sc query %SERVICE_NAME% >nul 2>&1
if not errorlevel 1 (
    echo [DEPLOY] Service exists, restarting...
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
) else (
    REM Boot-start driver: Start=0, Type=1 (KERNEL_DRIVER), ErrorControl=1
    sc create %SERVICE_NAME% type= kernel start= boot error= normal binPath= "System32\drivers\%DRIVER_FILE%" DisplayName= "AnXin Security Hypervisor"
    if errorlevel 1 (
        echo [ERROR] Failed to create service
        exit /b 1
    )
    echo [DEPLOY] Service created (boot-start)
)

REM Set load order group for early loading
reg add "HKLM\SYSTEM\CurrentControlSet\Services\%SERVICE_NAME%" /v Group /t REG_SZ /d "Early-Launch" /f >nul 2>&1

echo [DEPLOY] Starting service...
sc start %SERVICE_NAME%
if errorlevel 1 (
    echo [WARN] Service start failed (may require reboot for boot-start driver)
    echo        Error: %ERRORLEVEL%
) else (
    echo [DEPLOY] Service started successfully
)
goto :done

REM ─── Uninstall ─────────────────────────────────────────────────────
:uninstall_driver
echo [UNINSTALL] Removing %SERVICE_NAME%...

sc stop %SERVICE_NAME% >nul 2>&1
sc delete %SERVICE_NAME% >nul 2>&1
if errorlevel 1 (
    echo [WARN] Service deletion failed (may require reboot)
) else (
    echo [UNINSTALL] Service deleted
)

set DEST=%SystemRoot%\System32\drivers\%DRIVER_FILE%
if exist "%DEST%" (
    del /f "%DEST%" >nul 2>&1
    if exist "%DEST%" (
        echo [WARN] Driver file locked, will be removed on reboot
    ) else (
        echo [UNINSTALL] Driver file removed
    )
)
goto :done

REM ─── Create Test Certificate ───────────────────────────────────────
:create_test_cert
echo [CERT] Creating self-signed test certificate...
echo [CERT] Subject: CN=%TEST_CERT_NAME%

REM Use makecert if available (WDK), otherwise fall back to New-SelfSignedCertificate
where makecert >nul 2>&1
if not errorlevel 1 (
    makecert -r -pe -ss My -n "CN=%TEST_CERT_NAME%" -eku 1.3.6.1.5.5.7.3.3 -len 2048 -a sha256 "%~dp0%TEST_CERT_FILE%"
) else (
    echo [CERT] makecert not found, using PowerShell...
    powershell -NoProfile -Command ^
        "$cert = New-SelfSignedCertificate -Subject 'CN=%TEST_CERT_NAME%' -Type CodeSigningCert -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(5); Export-Certificate -Cert $cert -FilePath '%~dp0%TEST_CERT_FILE%'"
)

if errorlevel 1 (
    echo [ERROR] Certificate creation failed
    exit /b 1
)

echo [CERT] Certificate created and installed to CurrentUser\My store
echo [CERT] Exported to: %~dp0%TEST_CERT_FILE%
echo.
echo [INFO] To trust this certificate system-wide (optional):
echo        certutil -addstore Root %~dp0%TEST_CERT_FILE%
echo        certutil -addstore TrustedPublisher %~dp0%TEST_CERT_FILE%
echo.
echo [INFO] Enable test signing mode:
echo        bcdedit /set testsigning on
echo        (reboot required)
goto :done

REM ─── Done ──────────────────────────────────────────────────────────
:done
echo.
echo ============================================
echo  Complete.
echo ============================================
exit /b 0
