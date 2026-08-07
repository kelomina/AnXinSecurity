@echo off
set MSVC=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.52.36615
set WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.28000.0
set CL="%MSVC%\bin\Hostx64\x64\cl.exe"

echo #include ^<ntddk.h^> > "%~dp0test_sal.c"
echo VOID Test(_Out_ PULONG X, _In_ ULONG Y) { *X = Y; } >> "%~dp0test_sal.c"

%CL% /nologo /c /W4 /GS- /kernel /Zp8 /D_AMD64_ /DAMD64 /I "%WDK_INC%\km" /I "%WDK_INC%\shared" /I "%WDK_INC%\ucrt" /Fo"%~dp0test_sal.obj" "%~dp0test_sal.c"
echo EXIT: %ERRORLEVEL%

del "%~dp0test_sal.c" 2>nul
del "%~dp0test_sal.obj" 2>nul
