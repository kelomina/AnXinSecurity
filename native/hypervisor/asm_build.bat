@echo off
setlocal
set MSVC=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.52.36615
set SCRIPTDIR=%~dp0
set OBJ=%SCRIPTDIR%x64\Release\obj

echo   ml64 intel\entry_intel.asm
"%MSVC%\bin\Hostx64\x64\ml64.exe" /nologo /c /Zi /Fo"%OBJ%\entry_intel.obj" "%SCRIPTDIR%src\intel\entry_intel.asm"
if errorlevel 1 ( echo [ERROR] entry_intel.asm failed & exit /b 1 )

echo   ml64 amd\entry_amd.asm
"%MSVC%\bin\Hostx64\x64\ml64.exe" /nologo /c /Zi /Fo"%OBJ%\entry_amd.obj" "%SCRIPTDIR%src\amd\entry_amd.asm"
if errorlevel 1 ( echo [ERROR] entry_amd.asm failed & exit /b 1 )

echo [ASM] Done.
exit /b 0
