# diag-port4.ps1 - 从部署的 .sys 提取端口名 + 更多 FilterConnectCommunicationPort 变体。Host-side.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port4.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-port4 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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
public class FltProbe2 {
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
        return string.Format("name=[{0}] hr=0x{1:X8} (win32={2})", name, (uint)hr, hr & 0xFFFF);
    }
}
'@

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log, $csSrc)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-PORT4 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    GW "--- extract wide strings from deployed AnXinFileProtect.sys ---"
    $drv = 'C:\Windows\System32\drivers\AnXinFileProtect.sys'
    if (Test-Path $drv) {
        $bytes = [System.IO.File]::ReadAllBytes($drv)
        GW "  .sys size: $($bytes.Length) B"
        # scan for UTF-16LE printable strings >= 6 chars
        $sb = New-Object System.Text.StringBuilder
        $current = New-Object System.Collections.Generic.List[uint16]
        for ($i = 0; $i -lt $bytes.Length - 1; $i += 2) {
            $ch = [BitConverter]::ToUInt16($bytes, $i)
            if ($ch -ge 32 -and $ch -le 126) { $current.Add($ch) | Out-Null }
            else {
                if ($current.Count -ge 6) {
                    $s = -join ($current | ForEach-Object { [char]$_ })
                    if ($s -match 'ort|Port|nXin|ANXIN') { GW "    STR: $s" }
                }
                $current.Clear()
            }
        }
    } else { GW "  driver .sys NOT FOUND" }

    try {
        Add-Type -TypeDefinition $csSrc -Language CSharp -ErrorAction Stop
    } catch {
        GW "Add-Type FAILED: $($_.Exception.Message)"
        return
    }

    GW "--- FilterConnectCommunicationPort variants ---"
    foreach ($n in @(
        '\\AnXinFileProtectPort',
        'AnXinFileProtectPort',
        '\\Filter\\AnXinFileProtectPort',
        '\\AnXinFileProtectPort\\',
        '\\AnXinFileProtect',
        '\\AnxinFileProtectPort',
        '\\Device\\AnXinFileProtectPort',
        '\\AnXinFileProtectPort'
    )) {
        $r = [FltProbe2]::Try($n)
        GW "    $r"
    }

    "=== GUEST-PORT4 DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-port4-guest.log', $cs

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-port4-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port4-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-port4 done ==="
