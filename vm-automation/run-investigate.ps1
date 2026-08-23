# Host runner: start VM, connect via PS Direct, investigate why guest shuts down ~2min after boot.
# All-ASCII (Windows PowerShell 5.1 reads .ps1 as ANSI/GBK).
$ErrorActionPreference = 'Continue'
$vmId = '7b66415c-52cb-468e-b9bd-368746f42863'
$cred = New-Object System.Management.Automation.PSCredential('test', (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))

$vm = Get-VM -Id $vmId
if ($vm.State -ne 'Running') {
    try { Start-VM -VM $vm -ErrorAction Stop; "VM started at $(Get-Date -Format HH:mm:ss)" } catch { "start fail: $($_.Exception.Message)"; exit 1 }
    Start-Sleep -Seconds 20
}

# Poll PS Direct - catch the window before the ~2min guest shutdown
$deadline = (Get-Date).AddMinutes(9)
$connected = $false
$attempt = 0
while (-not $connected -and (Get-Date) -lt $deadline) {
    $attempt++
    $vm = Get-VM -Id $vmId
    if ($vm.State -ne 'Running') {
        "VM state=$($vm.State) at $(Get-Date -Format HH:mm:ss) - restarting..."
        try { Start-VM -VM $vm -ErrorAction Stop } catch {}
        Start-Sleep -Seconds 25
        continue
    }
    try {
        $s = New-PSSession -VMId $vmId -Credential $cred -ErrorAction Stop
        $connected = $true
        "CONNECTED attempt=$attempt at $(Get-Date -Format HH:mm:ss)"
    } catch {
        Start-Sleep -Seconds 6
    }
}
if (-not $connected) { "ERROR: never connected"; exit 1 }

# In-guest investigation (run fast, before shutdown)
$guestScript = @'
$ErrorActionPreference = 'Continue'
$log = 'C:\AnXinVmTest\investigate.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== investigate @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

W "--- shutdown events (1074/6008/41/1001) ---"
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074,6008,41,1001} -MaxEvents 8 -ErrorAction SilentlyContinue | ForEach-Object {
    W "[$($_.TimeCreated.ToString('HH:mm:ss'))] id=$($_.Id) src=$($_.ProviderName)"
}

W "--- 1074 full detail ---"
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074} -MaxEvents 4 -ErrorAction SilentlyContinue | ForEach-Object {
    W "1074: $($_.Message)"
}

W "--- recent System events (last 15 min, one-line) ---"
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-15)} -MaxEvents 80 -ErrorAction SilentlyContinue | ForEach-Object {
    W "[$($_.TimeCreated.ToString('HH:mm:ss'))] id=$($_.Id) $($_.ProviderName): $($_.Message.Split("`n")[0])"
}

W "--- anxin services ---"
sc.exe query type= service state= all 2>$null | Out-String -Stream | Select-String -Pattern 'anxin' -Context 0,1 | ForEach-Object { W $_.ToString() }

W "--- driverquery anxin ---"
driverquery.exe 2>$null | Select-String -Pattern 'anxin|AnXin' | ForEach-Object { W $_.ToString() }

W "--- scheduled tasks (shut/restart/fix/watchdog) ---"
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'shut|restart|fix|anxin|watch|recover|test|vm|boot' -or $_.Actions.Execute -match 'shutdown' } | ForEach-Object {
    $a = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '
    W "task: $($_.TaskPath)$($_.TaskName) state=$($_.State) action=[$a]"
}

W "--- service registry keys (all control sets) ---"
foreach ($cs in 'CurrentControlSet','ControlSet001','ControlSet002') {
    W "--- $cs ---"
    $base = "HKLM:\SYSTEM\$cs\Services"
    Get-ChildItem $base -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'anxin' } | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        W "key: $($_.PSChildName) Start=$($p.Start) Type=$($p.Type) ImagePath=$($p.ImagePath)"
    }
}

W "--- DiagFlags ---"
$d = Get-ItemProperty 'HKLM:\SOFTWARE\AnXinSecurity' -ErrorAction SilentlyContinue
W "DiagFlags = $($d.DiagFlags)"

W "--- shutdown watchdog source: Get-WinEvent 1074 all ---"
W "=== investigate done ==="
'@
try {
    $guestScript | Out-File -FilePath "$env:TEMP\investigate-guest.ps1" -Encoding ASCII
    Copy-Item "$env:TEMP\investigate-guest.ps1" -Destination 'C:\AnXinVmTest\investigate-guest.ps1' -ToSession $s -Force -ErrorAction Stop
    Invoke-Command -Session $s -ScriptBlock { & powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\AnXinVmTest\investigate-guest.ps1' } -ErrorAction Stop
} catch {
    "GUEST INVESTIGATE FAILED: $($_.Exception.Message)"
}
Remove-PSSession $s
"--- investigate log ---"
Copy-Item -Path 'C:\AnXinVmTest\investigate.log' -Destination "$env:TEMP\anxin-investigate.log" -FromSession $s -Force -ErrorAction SilentlyContinue
if (Test-Path "$env:TEMP\anxin-investigate.log") { Get-Content "$env:TEMP\anxin-investigate.log" } else { "no log copied" }
