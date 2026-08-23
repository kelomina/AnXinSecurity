@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul 2>&1
"C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe" "E:\Project\HTML\AnXinSecurity\native\driver\AnXinProcProtect.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:ClCompile /v:detailed > E:\Project\HTML\AnXinSecurity\native\driver\build_diag.log 2>&1
echo BUILDEXIT=%ERRORLEVEL%
