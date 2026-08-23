@echo off
for %%p in ("C:\Program Files\Microsoft Visual Studio\18" "C:\Program Files\Microsoft Visual Studio\18\Insiders") do (
    if exist "%%~p\MSBuild\Current\Bin\MSBuild.exe" (
        set MSBUILD="%%~p\MSBuild\Current\Bin\MSBuild.exe"
        goto :found
    )
)
:found
if "%MSBUILD%"=="" (echo NOTFOUND) else (echo FOUND)
echo DONE