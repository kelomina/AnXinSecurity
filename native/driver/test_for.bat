@echo off
setlocal enabledelayedexpansion
set MSBUILD=
for %%p in (
    "C:\Program Files\Microsoft Visual Studio\18\"
    "C:\Program Files\Microsoft Visual Studio\18\Insiders"
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise"
) do (
    if exist "%%~p\MSBuild\Current\Bin\MSBuild.exe" (
        set MSBUILD="%%~p\MSBuild\Current\Bin\MSBuild.exe"
        goto :found
    )
)
:found
if "%MSBUILD%"=="" (echo NOTFOUND) else (echo FOUND %MSBUILD%)