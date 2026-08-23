# diag-port.ps1 - diagnose AnXinFileProtect port connect failure root cause. Host-side.
# Steps: identify anxin-security processes -> stop AnXinSecurityService -> re-query ->
# if the service does not hold the port then the connect itself is broken (VUL-097 root
# cause may be connect failure, not path format). Restore service afterwards.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-port @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-PORT @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    $installDir = 'C:\Program Files\AnXinSecurity'
    $exe = Join-Path $installDir 'anxin-security.exe'

    GW "--- all anxin-security processes ---"
    Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object { GW "  pid=$($_.ProcessId) session=$($_.SessionId) cmdline=$($_.CommandLine)" }

    GW "--- query BEFORE service stop ---"
    (& cmd.exe /c "`"$exe`" --query-file-protect 2>&1") | ForEach-Object { GW "    $_" }

    GW "--- stop AnXinSecurityService ---"
    $svc = Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue
    if ($svc) {
        GW "  current state: $($svc.Status)"
        sc.exe stop AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 4
        $svc = Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue
        GW "  after stop: $($svc.Status)"
    } else { GW "  service not found" }
    Start-Sleep -Seconds 2

    GW "--- query AFTER service stop ---"
    (& cmd.exe /c "`"$exe`" --query-file-protect 2>&1") | ForEach-Object { GW "    $_" }

    GW "--- restart service ---"
    if ($svc) {
        sc.exe start AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 4
        $svc = Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue
        GW "  after restart: $($svc.Status)"
    }

    "=== GUEST-PORT DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-port-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-port-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-port-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-port done ==="
