@echo off
REM AnXinHypervisor - Direct cl.exe/link.exe build (no MSBuild/WDK toolset needed)
setlocal enabledelayedexpansion

set MSVC=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.52.36615
set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0
set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64
set CRT_INC=%MSVC%\include
set CRT_LIB=%MSVC%\lib\x64
set SRC=%~dp0src
set INC=%~dp0include
set OUT=%~dp0x64\Release
set OBJ=%OUT%\obj

if not exist "%OBJ%" mkdir "%OBJ%"
if not exist "%OUT%" mkdir "%OUT%"

set CL="%MSVC%\bin\Hostx64\x64\cl.exe"
set ML="%MSVC%\bin\Hostx64\x64\ml64.exe"
set LINK="%MSVC%\bin\Hostx64\x64\link.exe"

set CFLAGS=/nologo /c /W4 /O2 /Oi /GS- /kernel /Zp8 /Zi /D_AMD64_ /DAMD64 /DPOOL_NX_OPTIN=1 /DNDEBUG /FI "%INC%\sal_stub.h"
set INCLUDES=/I "%INC%" /I "%WDK_INC%\km" /I "%WDK_INC%\shared" /I "%MSVC%\include" /I "%WDK_INC%\ucrt"

echo [BUILD] AnXinHypervisor.sys (Release x64)
echo [BUILD] MSVC: %MSVC%
echo [BUILD] WDK:  %WDK_INC%
echo.

REM Compile all C sources
set SOURCES=driver debug hal exit_handler exit_cpuid exit_cr exit_msr hypercall page_table protect
set INTEL_SOURCES=intel_ops vmx vmcs ept
set AMD_SOURCES=amd_ops svm vmcb npt

set OBJ_FILES=

for %%f in (%SOURCES%) do (
    echo   cl %%f.c
    %CL% %CFLAGS% %INCLUDES% /Fo"%OBJ%\%%f.obj" "%SRC%\%%f.c"
    if errorlevel 1 ( echo [ERROR] %%f.c failed & exit /b 1 )
    set OBJ_FILES=!OBJ_FILES! "%OBJ%\%%f.obj"
)

for %%f in (%INTEL_SOURCES%) do (
    echo   cl intel\%%f.c
    %CL% %CFLAGS% %INCLUDES% /Fo"%OBJ%\%%f.obj" "%SRC%\intel\%%f.c"
    if errorlevel 1 ( echo [ERROR] intel\%%f.c failed & exit /b 1 )
    set OBJ_FILES=!OBJ_FILES! "%OBJ%\%%f.obj"
)

for %%f in (%AMD_SOURCES%) do (
    echo   cl amd\%%f.c
    %CL% %CFLAGS% %INCLUDES% /Fo"%OBJ%\%%f.obj" "%SRC%\amd\%%f.c"
    if errorlevel 1 ( echo [ERROR] amd\%%f.c failed & exit /b 1 )
    set OBJ_FILES=!OBJ_FILES! "%OBJ%\%%f.obj"
)

REM MASM objects are built by asm_build.bat (for-loop parser breaks ml64 invocations)
if not exist "%OBJ%\entry_intel.obj" ( echo [WARN] entry_intel.obj missing - run asm_build.bat )
if not exist "%OBJ%\entry_amd.obj" ( echo [WARN] entry_amd.obj missing - run asm_build.bat )

echo.
echo [C BUILD] All C sources compiled successfully.
exit /b 0
