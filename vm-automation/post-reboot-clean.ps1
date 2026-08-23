# post-reboot-clean.ps1 - T10 phase 2: after the guest reboots, verify the uninstall
# was FULLY clean: no driver services, no driver .sys files, no install dir, no
# uninstaller registry entry, no AnXin processes. Run on the host.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-post-reboot-clean.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== post-reboot-clean @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started @ $(Get-Date -Format HH:mm:ss)" }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(240); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 3
}
if (-not $s) { W "ERROR: PS Direct connect failed after reboot window"; exit 1 }
W "PS Direct connected @ $(Get-Date -Format HH:mm:ss)"

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    "=== GUEST-POST-REBOOT @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    GW "BOOT-TIME: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"

    GW "--- services (expect ALL gone / 1060) ---"
    $allGone = $true
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $gone = $q -match 'does not exist|1060'
        if (-not $gone) { $allGone = $false }
        GW "  $svc : $(if ($gone) { 'gone' } else { 'STILL-REGISTERED: ' + ((($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join '') })"
    }
    GW "SERVICES-CLEAN: $allGone"

    GW "--- driver files (expect NONE) ---"
    $sysLeft = @(Get-ChildItem 'C:\Windows\System32\drivers\AnXin*' -ErrorAction SilentlyContinue)
    if ($sysLeft.Count -eq 0) { GW "  no AnXin*.sys left - CLEAN" } else { $sysLeft | ForEach-Object { GW "  LEFT: $($_.Name) $($_.Length) B" } }
    GW "SYS-FILES-CLEAN: $($sysLeft.Count -eq 0)"

    GW "--- install dir (expect gone) ---"
    GW "INSTALL-DIR-GONE: $(-not (Test-Path 'C:\Program Files\AnXinSecurity'))"
    GW "APPDATA-LEFT: $((Test-Path "$env:ProgramData\AnXinSecurity") -or (Test-Path "$env:APPDATA\AnXinSecurity"))"

    GW "--- uninstaller registry (expect gone) ---"
    $unreg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'AnXin' }
    GW "UNINSTALL-REG-GONE: $(-not $unreg)"

    GW "--- processes (expect none) ---"
    $procs = @(Get-Process -Name 'anxin-security*','msedgewebview2' -ErrorAction SilentlyContinue)
    GW "PROCESSES-CLEAN: $($procs.Count -eq 0)"
    $procs | ForEach-Object { GW "  LEFT: $($_.Name) pid=$($_.Id)" }

    GW "--- PendingFileRenameOperations after boot (expect no AnXin entries) ---"
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $sysHits = @($pfro | Where-Object { $_ -match 'AnXin' }); GW "  AnXin PFRO entries: $($sysHits.Count)" } else { GW "  no PFRO" }

    "=== GUEST-POST-REBOOT DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-post-reboot-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-post-reboot-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-post-reboot-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== post-reboot-clean done ==="
