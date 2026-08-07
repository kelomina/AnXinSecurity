@echo off
set MSVC=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.52.36615
"%MSVC%\bin\Hostx64\x64\ml64.exe" /nologo /c /Zi /D_AMD64_ /Fo"x64\Release\obj\entry_intel.obj" "src\intel\entry_intel.asm"
echo EXIT CODE: %ERRORLEVEL%
