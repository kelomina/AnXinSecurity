@echo off
setlocal
set MSVC=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Tools\MSVC\14.52.36615
set WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64
set CRT_LIB=%MSVC%\lib\x64
set OBJ=%~dp0x64\Release\obj
set OUT=%~dp0x64\Release

"%MSVC%\bin\Hostx64\x64\link.exe" /nologo /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /BASE:0x10000 /INTEGRITYCHECK /DEBUG /PDB:"%OUT%\AnXinHypervisor.pdb" /OUT:"%OUT%\AnXinHypervisor.sys" /LIBPATH:"%WDK_LIB%" /LIBPATH:"%CRT_LIB%" ntoskrnl.lib hal.lib ntstrsafe.lib wdmsec.lib "%OBJ%\driver.obj" "%OBJ%\debug.obj" "%OBJ%\hal.obj" "%OBJ%\exit_handler.obj" "%OBJ%\exit_cpuid.obj" "%OBJ%\exit_cr.obj" "%OBJ%\exit_msr.obj" "%OBJ%\hypercall.obj" "%OBJ%\page_table.obj" "%OBJ%\protect.obj" "%OBJ%\intel_ops.obj" "%OBJ%\vmx.obj" "%OBJ%\vmcs.obj" "%OBJ%\ept.obj" "%OBJ%\amd_ops.obj" "%OBJ%\svm.obj" "%OBJ%\vmcb.obj" "%OBJ%\npt.obj" "%OBJ%\entry_intel.obj" "%OBJ%\entry_amd.obj"
echo EXIT: %ERRORLEVEL%
