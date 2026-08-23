# restart-and-verify.ps1 - reboot the guest, wait for it to come back, then check
# service states, NetFilter SCM recognition, driver boot load, and query-file-protect.
# Host-side. Requires user approval before running (guest reboot).
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-restart-verify.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== restart-and-verify @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id '7b66415c-52cb-468e-b9bd-368746f42863' -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))

# 1. trigger reboot inside the guest
$deadline = (Get-Date).AddSeconds(60); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $vm.Id -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if ($s) {
    try { Invoke-Command -Session $s -ScriptBlock { Restart-Computer -Force -ErrorAction SilentlyContinue } | Out-Null } catch {}
    Start-Sleep -Seconds 2
    Remove-PSSession $s -ErrorAction SilentlyContinue
    W "reboot triggered"
} else {
    W "WARN: could not connect to trigger reboot, will use Stop-VM/Start-VM"
    if ($vm.State -ne 'Off') { Stop-VM -VM $vm -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 5 }
    Start-VM -VM $vm
    W "VM restart via hypervisor"
}

# 2. wait for PS Direct to come back
$deadline = (Get-Date).AddSeconds(300); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $vm.Id -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 4
}
if (-not $s) { W "ERROR: PS Direct reconnect failed after reboot"; exit 1 }
W "reconnected after reboot"

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== POST-REBOOT @ $(Get-Date -Format HH:mm:ss) ==="
    "--- boot time ---"
    "  lastboot: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)"
    "--- services after reboot ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        $reg = if ($q -match 'does not exist|1060') { 'NOT-REGISTERED' } else { 'registered' }
        "  $svc : $reg $state"
    }
    "--- SCM driver enumeration (grep AnXin) ---"
    $all = & cmd.exe /c "sc query type= driver 2>&1" 2>&1 | Out-String
    ($all -split "`r?`n") | Where-Object { $_ -match 'AnXin' } | ForEach-Object { "  SCM: $_" }
    "--- loaded kernel modules (anxin) ---"
    $drv = & cmd.exe /c "driverquery /fo csv 2>&1" 2>&1 | Out-String
    ($drv -split "`r?`n") | Where-Object { $_ -match 'AnXin' } | ForEach-Object { "  DRV: $_" }
    "--- --query-file-protect after reboot ---"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $q3 = & cmd.exe /c "`"C:\Program Files\AnXinSecurity\anxin-security.exe`" --query-file-protect 2>&1" 2>&1
    $sw.Stop()
    "  elapsed=$([math]::Round($sw.Elapsed.TotalSeconds,2))s rc=$LASTEXITCODE"
    $q3 | ForEach-Object { "  Q: $_" }
    "--- running anxin processes ---"
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) pid=$($_.Id) path=$($_.Path)" }
    "--- app event log: service crash in last 5 min? ---"
    $since = (Get-Date).AddMinutes(-5)
    Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$since } -ErrorAction SilentlyContinue |
      Where-Object { $_.ProviderName -match 'Application Error|Service Control Manager|\.NET Runtime' } |
      Select-Object -First 5 TimeCreated, Id, ProviderName, @{n='m';e={($_.Message -split "`r?`n")[0]}} |
      ForEach-Object { "[$($_.TimeCreated.ToString('HH:mm:ss'))] id=$($_.Id) prov=$($_.ProviderName) $($_.m)" }
    "=== POST-REBOOT DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== restart-and-verify done ==="
