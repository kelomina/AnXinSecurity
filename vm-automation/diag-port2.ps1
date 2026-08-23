# diag-port2.ps1 - 用 C# P/Invoke 直接调用 FilterConnectCommunicationPort，获取真实 HRESULT。
# 不依赖 Rust 代码，可快速迭代端口名变体。Host-side.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port2.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-port2 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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

# C# P/Invoke source, passed to the guest
$cs = @'
using System;
using System.Runtime.InteropServices;
public class FltProbe {
    [DllImport("fltlib.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext,
        IntPtr lpSecurityAttributes, out IntPtr hPort);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    public static string Try(string name) {
        IntPtr h = IntPtr.Zero;
        int hr = FilterConnectCommunicationPort(name, 0, IntPtr.Zero, 0, IntPtr.Zero, out h);
        if (h != IntPtr.Zero) CloseHandle(h);
        return string.Format("name=[{0}] hr=0x{1:X8} (win32={2}) h=0x{3:X}",
            name, (uint)hr, hr & 0xFFFF, h.ToInt64());
    }
}
'@

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log, $csSrc)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-PORT2 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    try {
        Add-Type -TypeDefinition $csSrc -Language CSharp -ErrorAction Stop
        GW "Add-Type OK"
    } catch {
        GW "Add-Type FAILED: $($_.Exception.Message)"
        GW "Add-Type INNER: $($_.Exception.InnerException.Message)"
        return
    }

    GW "--- FilterConnectCommunicationPort variants ---"
    foreach ($n in @(
        '\\AnXinFileProtectPort',
        'AnXinFileProtectPort',
        '\\Filter\\AnXinFileProtectPort',
        '\\\\.\\AnXinFileProtectPort'
    )) {
        try {
            $r = [FltProbe]::Try($n)
            GW "  result: $r"
        } catch {
            GW "  THREW: $($_.Exception.Message)"
        }
    }

    GW "--- verify port object exists in kernel namespace (fltmc) ---"
    fltmc.exe 2>&1 | Select-Object -First 30 | ForEach-Object { GW "    $_" }
    GW "--- net/port: check loaded filter ---"
    fltmc.exe filters 2>&1 | Select-Object -First 30 | ForEach-Object { GW "    $_" }

    "=== GUEST-PORT2 DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-port2-guest.log', $cs

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-port2-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port2-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-port2 done ==="
