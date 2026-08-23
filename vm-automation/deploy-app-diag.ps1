# deploy-app-diag.ps1 - 部署带 HRESULT 诊断的 app，重启服务，抓服务侧 file-protect 注册日志，跑 query。Host-side.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LocalExe = 'E:\Project\HTML\AnXinSecurity\src-tauri\target\release\anxin-security.exe',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-deploy-app-diag.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== deploy-app-diag @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath
if (-not (Test-Path $LocalExe)) { W "ERROR: local exe not found: $LocalExe"; exit 1 }
W "local exe: $LocalExe ($((Get-Item $LocalExe).Length) B)"

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

# transfer new exe to guest temp first
$guestTmpExe = 'C:\Windows\Temp\anxin-new.exe'
Remove-Item -Path $guestTmpExe -ToSession $s -Force -ErrorAction SilentlyContinue
try {
    Copy-Item -Path $LocalExe -Destination $guestTmpExe -ToSession $s -Force -ErrorAction Stop
    W "transferred new exe to guest temp ($((Get-Item $LocalExe).Length) B)"
} catch {
    W "ERROR: transfer to guest failed: $($_.Exception.Message)"; Remove-PSSession $s; exit 1
}

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log, $exeName)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-DEPLOY @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    $install = 'C:\Program Files\AnXinSecurity'
    $svc = Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue
    GW "service before: $($svc.Status)  exe size: $((Get-Item (Join-Path $install 'anxin-security.exe') -ErrorAction SilentlyContinue).Length) B"

    # clear diag log
    Remove-Item 'C:\Windows\Temp\anxin-fp-diag.log' -Force -ErrorAction SilentlyContinue

    if ($svc -and $svc.Status -ne 'Stopped') {
        GW "stopping service..."
        sc.exe stop AnXinSecurityService 2>&1 | Out-Null
        Start-Sleep -Seconds 6
        GW "service after stop: $((Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue).Status)"
    }
    Start-Sleep -Seconds 2

    # stop any lingering anxin-security processes
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue | ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop; GW "  killed lingering pid $($_.Id)" } catch {} }

    GW "--- copy new exe ---"
    $src = 'C:\Windows\Temp\anxin-new.exe'
    $copyErr = $null
    try {
        Copy-Item -Path $src -Destination (Join-Path $install 'anxin-security.exe') -Force -ErrorAction Stop
        GW "  copy OK"
    } catch {
        $copyErr = $_.Exception.Message
        GW "  copy FAILED: $copyErr"
    }
    GW "exe size after: $((Get-Item (Join-Path $install 'anxin-security.exe') -ErrorAction SilentlyContinue).Length) B"

    # restart service
    GW "--- start service ---"
    sc.exe start AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 8
    GW "service after start: $((Get-Service -Name 'AnXinSecurityService' -ErrorAction SilentlyContinue).Status)"

    GW "--- diag log content ---"
    Get-Content 'C:\Windows\Temp\anxin-fp-diag.log' -ErrorAction SilentlyContinue | ForEach-Object { GW "    $_" }

    GW "--- run --query-file-protect (authorized CLI) ---"
    $q = & cmd.exe /c "`"$install\anxin-security.exe`" --query-file-protect 2>&1"
    $q | ForEach-Object { GW "    $_" }

    "=== GUEST-DEPLOY DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-deploy-app-diag-guest.log', 'anxin-security.exe'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-deploy-app-diag-guest.log' -Destination $LogPath -Append -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== deploy-app-diag done ==="
