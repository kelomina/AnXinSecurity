@echo off
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
) do if exist "%%~p\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=%%~p\MSBuild\Current\Bin\MSBuild.exe"
if "%MSBUILD%"=="" (echo NOTFOUND) else (echo FOUND %MSBUILD%)
echo DONE