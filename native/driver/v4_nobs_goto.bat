@echo off
for %%p in ("C:\Program Files\Microsoft Visual Studio\18" "C:\Program Files\Microsoft Visual Studio\18\Insiders") do (
    if exist "%%~p\MSBuild\Current\Bin\MSBuild.exe" (
        goto :found
    )
)
:found
echo DONE