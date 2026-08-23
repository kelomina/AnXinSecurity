# Elevated: mount broken child, survey WHY it shuts down ~2min after boot, WITHOUT needing the guest to be up.
# Reads: (a) scheduled task XMLs, (b) System.evtx shutdown/bsod events, (c) AnXin service registry keys.
# All-ASCII.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-offline-survey.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== offline-survey @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    W "ERROR: not elevated"; exit 1
}
W "elevated OK"

$broken = Get-ChildItem 'D:\Virtual Hard Disks' -Filter '*31EECB48*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.avhdx' } | Select-Object -First 1
if (-not $broken) { W "ERROR: broken child not found"; exit 1 }
W "broken child: $($broken.FullName)"

try { Mount-VHD -Path $broken.FullName -NoDriveLetter -ErrorAction Stop; W "mounted" } catch { W "mount fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 4

$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match '31EECB48') -or ($_.FriendlyName -match '31EECB48') } | Select-Object -First 1
if (-not $disk) { W "ERROR: cannot locate mounted disk"; exit 1 }
if ($disk.IsOffline) { try { Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop; W "brought online" } catch {} }

$part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 10GB } | Sort-Object Size -Descending | Select-Object -First 1
if (-not $part) { W "ERROR: no big partition"; exit 1 }
if (-not $part.DriveLetter) {
    $used = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { $_.DriveLetter })
    $cand = @('X','V','W','Z') | Where-Object { $used -notcontains $_ } | Select-Object -First 1
    if (-not $cand) { $cand = 'X' }
    try { Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $cand -ErrorAction Stop; W "assigned $cand" } catch {}
}
$part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
$letter = $part.DriveLetter
if (-not $letter) { W "ERROR: no letter"; exit 1 }
W "mount: $letter`:\"

$win = "$letter`:\Windows"
$tasks = "$win\System32\Tasks"
W "--- scheduled task files (all) ---"
if (Test-Path $tasks) {
    Get-ChildItem $tasks -Filter '*.xml' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $xml = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
        # look for anything that executes shutdown/restart or poweroff-ish commands
        if ($xml -match 'shutdown|restart|powercfg.*hibernate|Stop-Computer|StopComputer|vmconnect|Virtual') {
            W "TASK: $($_.FullName.Substring($tasks.Length))"
            $xml -split "`r?`n" | Select-String -Pattern 'Command|Arguments|StartBoundary|Enabled|UserId' | ForEach-Object { W "    $($_.Line.Trim())" }
        }
    }
    W "--- all task file names ---"
    Get-ChildItem $tasks -Filter '*.xml' -Recurse -ErrorAction SilentlyContinue | ForEach-Object { W "taskfile: $($_.FullName.Substring($tasks.Length))" }
} else { W "no tasks dir" }

$evtx = "$win\System32\winevt\Logs\System.evtx"
W "--- System.evtx shutdown events (1074/6008/41/1001) ---"
if (Test-Path $evtx) {
    $out = wevtutil.exe qe "$evtx" /q:"*[System[(EventID=1074 or EventID=6008 or EventID=41 or EventID=1001)]]" /f:text /c:20 2>&1 | Out-String
    $out -split "`r?`n" | ForEach-Object { W $_.TrimEnd() }
} else { W "no System.evtx" }

$cfg = "$letter`:\Windows\System32\config"
W "--- AnXin service keys across all control sets ---"
$ld = reg.exe load HKLM\RX_SYSTEM "$cfg\SYSTEM" 2>&1 | Out-String; W "load SYSTEM: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SYSTEM') {
    foreach ($cs in 'ControlSet001','ControlSet002','CurrentControlSet') {
        W "--- $cs ---"
        Get-ChildItem "HKLM:\RX_SYSTEM\$cs\Services" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'anxin' } | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            W "key: $($_.PSChildName) Start=$($p.Start) Type=$($p.Type) ImagePath=$($p.ImagePath)"
        }
    }
    W "--- boot-start drivers referencing AnXin (Start=0, image path contains anxin or driver) ---"
    Get-ChildItem 'HKLM:\RX_SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.Start -eq 0 -and $p.ImagePath -match 'anxin|AnXin|\.sys') { W "bootstart: $($_.PSChildName) -> $($p.ImagePath)" }
    }
    $un = reg.exe unload HKLM\RX_SYSTEM 2>&1 | Out-String; W "unload SYSTEM: $($un.Trim())"
} else { W "SYSTEM hive did not load" }

W "--- DiagFlags (SOFTWARE) ---"
$ld = reg.exe load HKLM\RX_SOFTWARE "$cfg\SOFTWARE" 2>&1 | Out-String; W "load SOFTWARE: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SOFTWARE\AnXinSecurity') { W "DiagFlags = $((Get-ItemProperty 'HKLM:\RX_SOFTWARE\AnXinSecurity').DiagFlags)" } else { W "no AnXinSecurity SOFTWARE key" }
$un = reg.exe unload HKLM\RX_SOFTWARE 2>&1 | Out-String; W "unload SOFTWARE: $($un.Trim())"

try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== offline-survey done ==="
