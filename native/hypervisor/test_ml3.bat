@echo off
setlocal enabledelayedexpansion
set MSVC=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.52.36615
set OBJ=%~dp0x64\Release\obj
set SCRIPTDIR=%~dp0
echo OBJ=%OBJ%
echo SCRIPTDIR=%SCRIPTDIR%
echo SOURCE=%SCRIPTDIR%src\intel\entry_intel.asm
echo ---
"%MSVC%\bin\Hostx64\x64\ml64.exe" /nologo /c /Zi /Fo"%OBJ%\entry_intel.obj" "%SCRIPTDIR%src\intel\entry_intel.asm"
echo EXIT: %ERRORLEVEL%
