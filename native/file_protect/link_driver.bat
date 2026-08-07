@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\Tools\VsDevCmd.bat" >nul 2>&1
link /OUT:"e:\Project\HTML\AnXinSecurity\native\file_protect\build\x64\Release\AnXinFileProtect.sys" ^
  /VERSION:"10.0" /INCREMENTAL:NO /NOLOGO /WX /SECTION:"INIT,d" ^
  "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64\fltMgr.lib" ^
  "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64\BUFFEROVERFLOWFASTFAILK.LIB" ^
  "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64\NTOSKRNL.LIB" ^
  "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64\HAL.LIB" ^
  "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\km\x64\WMILIB.LIB" ^
  /NODEFAULTLIB /MANIFEST:NO /DEBUG ^
  /PDB:"e:\Project\HTML\AnXinSecurity\native\file_protect\build\x64\Release\AnXinFileProtect.pdb" ^
  /SUBSYSTEM:NATIVE,"10.00" /Driver /OPT:REF /OPT:ICF ^
  /ENTRY:"GsDriverEntry" /RELEASE ^
  /IMPLIB:"e:\Project\HTML\AnXinSecurity\native\file_protect\build\x64\Release\AnXinFileProtect.lib" ^
  /MERGE:"_TEXT=.text;_PAGE=PAGE" /MACHINE:X64 /PROFILE /guard:cf /kernel ^
  /IGNORE:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221,4108,4088,4218,4218,4235 ^
  /osversion:10.0 /pdbcompress /debugtype:pdata ^
  "e:\Project\HTML\AnXinSecurity\native\file_protect\build\x64\Release\obj\minifilter.obj"
if %ERRORLEVEL% equ 0 (
  echo LINK SUCCESS
  dir "e:\Project\HTML\AnXinSecurity\native\file_protect\build\x64\Release\AnXinFileProtect.sys"
) else (
  echo LINK FAILED with error %ERRORLEVEL%
)
