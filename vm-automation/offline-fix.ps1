# Elevated: mount broken AVHDX, fix offline registry, dismount. All-ASCII.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-offline-fix.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== offline-fix @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

# 0. verify elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    W "ERROR: not elevated"; exit 1
}
W "elevated OK"

# 1. find the broken child by its GUID (ASCII, avoids the Chinese filename)
$broken = Get-ChildItem 'D:\Virtual Hard Disks' -Filter '*31EECB48*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.avhdx' } | Select-Object -First 1
if (-not $broken) { W "ERROR: broken child not found"; Get-ChildItem 'D:\Virtual Hard Disks' | ForEach-Object { W "disk: $($_.Name)" }; exit 1 }
W "broken child: $($broken.FullName)"

# 2. mount
try {
    Mount-VHD -Path $broken.FullName -NoDriveLetter -ErrorAction Stop
    W "mounted"
} catch { W "mount fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 4

# 3. identify the mounted disk
$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match '31EECB48') -or ($_.FriendlyName -match '31EECB48') } | Select-Object -First 1
if (-not $disk) {
    W "no disk matched by GUID; dumping all disks"
    Get-Disk | ForEach-Object { W "disk $($_.Number): '$($_.FriendlyName)' loc='$($_.Location)' offline=$($_.IsOffline) size=$([math]::Round($_.Size/1GB))GB" }
    W "ERROR: cannot locate mounted disk"
    exit 1
}
W "mounted disk #$($disk.Number): '$($disk.FriendlyName)'"

# 4. bring online if offline
if ($disk.IsOffline) {
    try { Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop; W "brought online" } catch { W "online fail: $($_.Exception.Message)" }
}

# 5. find Windows partition and assign a drive letter
$part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 10GB } | Sort-Object Size -Descending | Select-Object -First 1
if (-not $part) { W "ERROR: no big partition"; Get-Partition -DiskNumber $disk.Number | ForEach-Object { W "part $($_.PartitionNumber) size=$([math]::Round($_.Size/1GB))GB" }; exit 1 }
if (-not $part.DriveLetter) {
    $used = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { $_.DriveLetter })
    $cand = @('X','V','W','Z') | Where-Object { $used -notcontains $_ } | Select-Object -First 1
    if (-not $cand) { $cand = 'X' }
    try { Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $cand -ErrorAction Stop; W "assigned letter $cand" } catch { W "letter fail: $($_.Exception.Message)" }
}
$part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
$letter = $part.DriveLetter
if (-not $letter) { W "ERROR: no drive letter"; exit 1 }
$cfg = "$letter`:\Windows\System32\config"
W "hive dir: $cfg"
if (-not (Test-Path "$cfg\SYSTEM")) { W "ERROR: no SYSTEM hive at $cfg"; exit 1 }

# 6. reg load both hives
$ld = reg.exe load HKLM\RX_SOFTWARE "$cfg\SOFTWARE" 2>&1 | Out-String; W "load SOFTWARE: $($ld.Trim())"
$ld = reg.exe load HKLM\RX_SYSTEM "$cfg\SYSTEM" 2>&1 | Out-String; W "load SYSTEM: $($ld.Trim())"

# 7. set DiagFlags to the given value (default 0 = all features enabled; 12 = ObCallbacks disabled)
$flags = 0
if ($args.Count -gt 0) { $flags = [int]$args[0] }
try {
    $p = 'HKLM:\RX_SOFTWARE\AnXinSecurity'
    New-Item -Path $p -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $p -Name 'DiagFlags' -Value $flags -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    W "DiagFlags set = $((Get-ItemProperty $p).DiagFlags)"
} catch { W "DiagFlags fail: $($_.Exception.Message)" }

# 8. optional: set service Start values from args[1] (default 4=disabled; pass -1 to skip)
$svcNames = 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService'
$svcStart = 4
if ($args.Count -gt 1) { $svcStart = [int]$args[1] }
if ($svcStart -ge 0) {
    foreach ($n in $svcNames) {
        $key = "HKLM:\RX_SYSTEM\CurrentControlSet\Services\$n"
        if (Test-Path $key) {
            try { Set-ItemProperty -Path $key -Name 'Start' -Value $svcStart -ErrorAction Stop; W "set $n Start=$svcStart" } catch { W "svc $n fail: $($_.Exception.Message)" }
        } else { W "svc $n not present (CurrentControlSet)" }
    }
} else { W "skipping service Start changes" }

# 9. verify
W "--- verify ---"
W "DiagFlags = $((Get-ItemProperty 'HKLM:\RX_SOFTWARE\AnXinSecurity' -ErrorAction SilentlyContinue).DiagFlags)"
Get-ChildItem 'HKLM:\RX_SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'anxin' } | ForEach-Object { W "svc key $($_.PSChildName) start=$((Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Start)" }

# 10. unload + dismount
$un = reg.exe unload HKLM\RX_SOFTWARE 2>&1 | Out-String; W "unload SOFTWARE: $($un.Trim())"
$un = reg.exe unload HKLM\RX_SYSTEM 2>&1 | Out-String; W "unload SYSTEM: $($un.Trim())"
try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== offline-fix done ==="
