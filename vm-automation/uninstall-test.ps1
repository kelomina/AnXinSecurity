# uninstall-test.ps1 - cleanly remove the current AnXin install from the guest
# (run the NSIS uninstaller silently, poll until gone), so the re-install test
# starts from a clean slate.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-uninstall-test.log',
    [int]$TimeoutSec = 180
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== uninstall-test @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    param($timeoutSec, $log)
    function GW([string]$m) { Add-Content -Path $log -Value $m }
    "=== GUEST-UNINSTALL @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    "ELEVATED: $isAdmin"
    $u = 'C:\Program Files\AnXinSecurity\uninstall.exe'
    if (-not (Test-Path $u)) { "NO-UNINSTALLER - nothing to uninstall"; "=== GUEST-UNINSTALL DONE ===" | Add-Content $log; return }
    if ($isAdmin) {
        $p = Start-Process -FilePath $u -ArgumentList '/S' -PassThru
    } else {
        $p = Start-Process -FilePath $u -ArgumentList '/S' -Verb RunAs -PassThru
    }
    "UNINSTALL-LAUNCHED pid=$($p.Id)"
    $deadline = (Get-Date).AddSeconds($timeoutSec); $done = $false
    while ((Get-Date) -lt $deadline) {
        $unP = @(Get-Process -Name 'uninstall' -ErrorAction SilentlyContinue)
        $dirGone = -not (Test-Path 'C:\Program Files\AnXinSecurity')
        $svcGone = ((sc.exe query AnXinSecurityService 2>&1 | Out-String) -match '1060|does not exist')
        if ($unP.Count -eq 0 -and $dirGone) { $done = $true; break }
        Start-Sleep -Seconds 3
    }
    if ($done) { "UNINSTALL-DONE dirGone=$dirGone svcGone=$svcGone" } else { "UNINSTALL-TIMEOUT dirGone=$dirGone svcGone=$svcGone" }
    Start-Sleep -Seconds 3
    "--- services after uninstall ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        if ($q -match 'does not exist|1060') { "$svc : gone" } else { "$svc : " + ((($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join '') }
    }
    "--- driver files after uninstall ---"
    (Get-ChildItem 'C:\Windows\System32\drivers\AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name)" })
    "--- install dir after ---"
    if (Test-Path 'C:\Program Files\AnXinSecurity') { "  still exists" } else { "  gone" }
    "=== GUEST-UNINSTALL DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
} -ArgumentList $TimeoutSec, 'C:\Windows\Temp\anxin-uninstall-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-uninstall-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-uninstall-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== uninstall-test done ==="
