# diag-port7.ps1 - 用伪装授权身份的进程测试端口连接，区分"未授权"vs"第二客户端"。Host-side.
# 复制 powershell.exe 到 C:\Windows\Temp\anxinsecurity\anxin-security.exe，使其满足驱动的
# IsCallerAuthorized（路径含 \anxinsecurity\ 且以 \anxin-security.exe 结尾）。从该进程执行
# FilterConnectCommunicationPort，观察 HRESULT。
# 用 -File 方式运行临时 .ps1（避免 -Command 字符串因 C# 双引号破坏命令行参数引用）。
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port7.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-port7 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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

# C# probe source (written to a .cs file on guest, avoids command-line quoting)
$cs = @'
using System;
using System.Runtime.InteropServices;
public class FltProbe7 {
    [DllImport("fltlib.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int FilterConnectCommunicationPort(
        string lpPortName, uint dwOptions, IntPtr lpContext, ushort wSizeOfContext,
        IntPtr lpSecurityAttributes, out IntPtr hPort);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    public static string Try(string name) {
        IntPtr h = IntPtr.Zero;
        int hr = FilterConnectCommunicationPort(name, 0, IntPtr.Zero, 0, IntPtr.Zero, out h);
        string r;
        if (h != IntPtr.Zero) {
            CloseHandle(h);
            r = string.Format("CONNECTED name=[{0}] hr=0x{1:X8} h=0x{2:X}", name, (uint)hr, h.ToInt64());
        } else {
            r = string.Format("DENIED name=[{0}] hr=0x{1:X8} (win32={2})", name, (uint)hr, hr & 0xFFFF);
        }
        return r;
    }
}
'@

# inner .ps1 script that runs AS the spoofed anxin-security.exe (via -File)
$inner = @'
param([string]$CsPath, [string]$Log)
function GW([string]$m) { Add-Content -Path $Log -Value $m; Write-Output $m }
GW "PID=$([System.Diagnostics.Process]::GetCurrentProcess().Id) IMAGE=$([System.IO.Path]::GetFileName([Environment]::GetCommandLineArgs()[0]))"
try {
    $src = [System.IO.File]::ReadAllText($CsPath)
    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop
    GW "ADDTYPE-OK"
} catch {
    GW ("ADDTYPE-FAIL: " + $_.Exception.Message)
    exit
}
$r = [FltProbe7]::Try('\AnXinFileProtectPort')
GW ("RESULT: " + $r)
$r2 = [FltProbe7]::Try('\AnXinFileProtectPort')
GW ("RESULT2: " + $r2)
'@

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log, $csSrc, $innerSrc)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-PORT7 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    $dir = 'C:\Windows\Temp\anxinsecurity'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $spoof = Join-Path $dir 'anxin-security.exe'
    Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $spoof -Force
    $csFile = Join-Path $dir 'probe.cs'
    $innerFile = Join-Path $dir 'inner.ps1'
    Set-Content -Path $csFile -Value $csSrc -Encoding UTF8
    Set-Content -Path $innerFile -Value $innerSrc -Encoding UTF8
    $innerLog = 'C:\Windows\Temp\anxin-diag-port7-inner.log'
    GW "spoofed exe created: $spoof ($((Get-Item $spoof).Length) B)"

    function RunSpoof {
        Remove-Item $innerLog -Force -ErrorAction SilentlyContinue
        $o = & $spoof -NoProfile -ExecutionPolicy Bypass -File $innerFile -CsPath $csFile -Log $innerLog 2>&1
        $code = $LASTEXITCODE
        GW "  exit code: $code"
        $o | ForEach-Object { GW "    $_" }
        Get-Content $innerLog -ErrorAction SilentlyContinue | ForEach-Object { GW "    LOG: $_" }
    }

    GW "--- test 1: connect while service RUNNING (from spoofed authorized process) ---"
    RunSpoof

    GW "--- stop service, retest ---"
    $svc = Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue
    if ($svc) {
        sc.exe stop AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 5
        GW "  service state: $((Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue).Status)"
    }
    RunSpoof

    GW "--- restart service ---"
    if ($svc) {
        sc.exe start AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 5
        GW "  service state: $((Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue).Status)"
    }
    Remove-Item $spoof -Force -ErrorAction SilentlyContinue
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue

    "=== GUEST-PORT7 DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-port7-guest.log', $cs, $inner

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-port7-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port7-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-port7-inner.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port7-inner.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-port7 done ==="
