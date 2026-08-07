@echo off
REM AnXinHypervisor full build: C compile + ASM + link
REM Each step runs in its own cmd context to avoid enabledelayedexpansion leaking.

echo === Step 1: C Compilation ===
cmd /c "%~dp0build_direct.bat"
if errorlevel 1 ( echo [FAILED] C compilation & exit /b 1 )

echo.
echo === Step 2: ASM Assembly ===
cmd /c "%~dp0asm_build.bat"
if errorlevel 1 ( echo [FAILED] ASM assembly & exit /b 1 )

echo.
echo === Step 3: Link ===
cmd /c "%~dp0link_build.bat"
if errorlevel 1 ( echo [FAILED] Link & exit /b 1 )

exit /b 0
