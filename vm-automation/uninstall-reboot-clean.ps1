# uninstall-reboot-clean.ps1 - T10 phase 1: silently uninstall, verify the .sys
# reboot-delete registrations landed in PendingFileRenameOperations (VUL-101 fix),
# then REBOOT the guest. Phase 2 (post-reboot-clean.ps1) verifies full cleanup.
# Host-side script. Guest reboot requires prior user approval.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-uninstall-reboot.log',
    [int]$TimeoutSec = 180
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== uninstall-reboot-clean @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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
    param($timeoutSec, $log)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-UNINSTALL @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    GW "ELEVATED: $isAdmin"

    # stop the UI so it does not hold the exe / fight the uninstaller
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $u = 'C:\Program Files\AnXinSecurity\uninstall.exe'
    if (-not (Test-Path $u)) { GW "NO-UNINSTALLER"; "=== GUEST-UNINSTALL DONE ===" | Add-Content $log; return }
    if ($isAdmin) { $p = Start-Process -FilePath $u -ArgumentList '/S' -PassThru }
    else { $p = Start-Process -FilePath $u -ArgumentList '/S' -Verb RunAs -PassThru }
    GW "UNINSTALL-LAUNCHED pid=$($p.Id)"

    $deadline = (Get-Date).AddSeconds($timeoutSec); $done = $false; $lastState = ''
    while ((Get-Date) -lt $deadline) {
        $unP = @(Get-Process -Name 'uninstall' -ErrorAction SilentlyContinue)
        $dirGone = -not (Test-Path 'C:\Program Files\AnXinSecurity')
        $lastState = "unP=$($unP.Count) dirGone=$dirGone"
        if ($unP.Count -eq 0 -and $dirGone) { $done = $true; break }
        Start-Sleep -Seconds 3
    }
    GW $(if ($done) { "UNINSTALL-DONE $lastState" } else { "UNINSTALL-TIMEOUT $lastState" })
    Start-Sleep -Seconds 3

    GW "--- PendingFileRenameOperations (expect AnXin*.sys entries - VUL-101 fix) ---"
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) {
        $sysHits = $pfro | Where-Object { $_ -match 'AnXin.*\.sys' }
        GW "PFRO entries: $($pfro.Count)"
        $pfro | ForEach-Object { GW "  PFRO: $_" }
        GW "SYS-ENTRIES: $($sysHits.Count)"
    } else { GW "PFRO: none" }

    GW "--- services after uninstall (drivers may be marked-for-delete until reboot) ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        GW "  $svc : $(if ($q -match 'does not exist|1060') { 'gone' } else { ((($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join '') })"
    }
    GW "--- driver files still present now (should be deleted at reboot) ---"
    (Get-ChildItem 'C:\Windows\System32\drivers\AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { GW "  $($_.Name) $($_.Length) B" })

    GW "REBOOTING GUEST..."
    & shutdown.exe /r /t 3 /f
    GW "REBOOT-ISSUED"
    "=== GUEST-UNINSTALL DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
} -ArgumentList $TimeoutSec, 'C:\Windows\Temp\anxin-uninstall-reboot-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-uninstall-reboot-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-uninstall-reboot-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== uninstall-reboot-clean done (guest now rebooting) ==="
