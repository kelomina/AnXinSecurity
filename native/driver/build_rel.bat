@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul 2>&1
"C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\MSBuild.exe" "E:\Project\HTML\AnXinSecurity\native\driver\AnXinProcProtect.vcxproj" /p:Configuration=Release /p:Platform=x64 /p:WindowsTargetPlatformVersion=10.0.28000.0 "/p:SignMode=" "/p:EnableInfVerification=false" /t:Rebuild /v:minimal
echo BUILDEXIT=%ERRORLEVEL%
