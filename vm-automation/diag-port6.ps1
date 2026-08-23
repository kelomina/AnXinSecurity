# diag-port6.ps1 - test FilterConnectCommunicationPort with the CORRECT single-backslash name.
# PowerShell single quotes are literal: '\\X' = TWO backslashes. A single backslash is '\X'.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port6.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-port6 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; Start-Sleep -Seconds 15 }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$cs = @'
using System;
using System.Runtime.InteropServices;
public class FltProbe3 {
    [DllImport("fltlib.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext,
        IntPtr lpSecurityAttributes, out IntPtr hPort);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    public static string Try(string name) {
        IntPtr h = IntPtr.Zero;
        int hr = FilterConnectCommunicationPort(name, 0, IntPtr.Zero, 0, IntPtr.Zero, out h);
        int gle = Marshal.GetLastWin32Error();
        if (h != IntPtr.Zero) CloseHandle(h);
        return string.Format("name=[{0}] hr=0x{1:X8} (win32={2}) h=0x{3:X} gle={4}",
            name, (uint)hr, hr & 0xFFFF, h.ToInt64(), gle);
    }
}
'@

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log, $csSrc)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-PORT6 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    try {
        Add-Type -TypeDefinition $csSrc -Language CSharp -ErrorAction Stop
        GW "Add-Type OK"
    } catch {
        GW "Add-Type FAILED: $($_.Exception.Message)"
        return
    }
    # PowerShell literal: '\AnXinFileProtectPort' is a SINGLE backslash. '\\' would be two.
    $variants = @(
        '\AnXinFileProtectPort',
        '\Device\AnXinFileProtectPort',
        'AnXinFileProtectPort',
        '\AnXinFileProtectPort'  # repeat for consistency
    )
    foreach ($n in $variants) {
        $r = [FltProbe3]::Try($n)
        GW "    $r"
    }
    "=== GUEST-PORT6 DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-port6-guest.log', $cs

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-port6-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port6-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-port6 done ==="
