# setdiag-test.ps1 - run on the guest as the "test" user. Opens
# \\.\AnXinProcProtect and issues IOCTL_ANXIN_SET_DIAG=0x0022A028 with value 0xF.
# VUL-099 expects this to be REFUSED for a non-SYSTEM/non-trusted caller.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AnxIo {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] ib, uint il, byte[] ob, uint ol, out uint r, IntPtr ov);
  [DllImport("kernel32.dll")]
  public static extern bool CloseHandle(IntPtr h);
}
'@
$h = [AnxIo]::CreateFile("\\.\AnXinProcProtect", [uint32]3221225472, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr]::Zero -or $h -eq [IntPtr](-1)) { Write-Output "OPEN-FAIL err=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"; exit }
$in = [BitConverter]::GetBytes([uint32]0xF)
$out = New-Object byte[] 4
$ret = 0
$ok = [AnxIo]::DeviceIoControl($h, [uint32]0x0022A028, $in, [uint32]$in.Length, $out, [uint32]$out.Length, [ref]$ret, [IntPtr]::Zero)
if ($ok) { Write-Output "SENT-OK" } else { Write-Output "REFUSED err=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
[AnxIo]::CloseHandle($h) | Out-Null
