@echo off
set SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe
set SYS=%~dp0x64\Release\AnXinHypervisor.sys

echo [SIGN] Signing %SYS%
"%SIGNTOOL%" sign /v /s My /sha1 CA21B971BC2EA0201E2AA568B230A0035212246E /fd SHA256 "%SYS%"
if errorlevel 1 (
    echo [SIGN] Failed
    exit /b 1
)
echo [SIGN] Success
echo.
echo [VERIFY] Checking signature...
"%SIGNTOOL%" verify /v "%SYS%"
exit /b 0
