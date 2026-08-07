@echo off
REM AnXinHypervisor - Benchmark Build & Run Script
REM
REM Usage:
REM   run_benchmark.bat              Build and run single pass
REM   run_benchmark.bat compare      Run baseline vs active comparison
REM   run_benchmark.bat json         Output JSON format

setlocal enabledelayedexpansion

set ACTION=%1
if "%ACTION%"=="" set ACTION=run

REM Locate MSVC
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

call "%VS_PATH%\%VS_EDITION%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1

REM Build
echo [BUILD] Compiling bench_hypervisor.c ...
cl /O2 /W4 /nologo "%~dp0bench_hypervisor.c" /Fe"%~dp0bench_hv.exe" /link /out:"%~dp0bench_hv.exe"
if errorlevel 1 (
    echo [ERROR] Build failed
    exit /b 1
)
echo [BUILD] OK: %~dp0bench_hv.exe
echo.

if "%ACTION%"=="json" (
    "%~dp0bench_hv.exe" --json
    goto :done
)

if "%ACTION%"=="compare" goto :compare

REM Single run
"%~dp0bench_hv.exe" --iterations 2000000
goto :done

:compare
echo ============================================
echo  COMPARISON MODE
echo  This requires two runs:
echo    1. With hypervisor NOT loaded (baseline)
echo    2. With hypervisor ACTIVE
echo ============================================
echo.

echo [PASS 1] Baseline (hypervisor should NOT be loaded)
echo Press Enter when ready...
pause >nul
"%~dp0bench_hv.exe" --json --iterations 2000000 > "%~dp0result_baseline.json"
echo [PASS 1] Saved to result_baseline.json
echo.

echo [PASS 2] Active (hypervisor should be loaded)
echo Press Enter when ready...
pause >nul
"%~dp0bench_hv.exe" --json --iterations 2000000 > "%~dp0result_active.json"
echo [PASS 2] Saved to result_active.json
echo.

echo [ANALYSIS] Computing overhead...
echo.
echo Compare the two JSON files manually or use:
echo   python compare_results.py result_baseline.json result_active.json
echo.
echo Target: less than 3%% overhead on all metrics.

:done
echo.
echo Done.
exit /b 0
