# Elevated: mount broken child, list C:\Users profiles, enumerate SAM user accounts,
# read Winmgmt/Schedule service Start values + 360-related service keys (read-only).
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-sam.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== sam @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated"; exit 1 }

$broken = Get-ChildItem 'D:\Virtual Hard Disks' -Filter '*31EECB48*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.avhdx' } | Select-Object -First 1
if (-not $broken) { W "ERROR: broken child not found"; exit 1 }
try { Mount-VHD -Path $broken.FullName -NoDriveLetter -ErrorAction Stop; W "mounted" } catch { W "mount fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 4
$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match '31EECB48') -or ($_.FriendlyName -match '31EECB48') } | Select-Object -First 1
if (-not $disk) { W "ERROR: disk not found"; exit 1 }
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
$win = "$letter`:\Windows"
W "mount: $letter`:\"

W "--- C:\Users profiles ---"
$usersDir = "$letter`:\Users"
if (Test-Path $usersDir) { Get-ChildItem $usersDir -Force -ErrorAction SilentlyContinue | ForEach-Object { W "  user-profile: $($_.Name)" } } else { W "  no Users dir" }

W "--- SAM hive user names ---"
$ld = reg.exe load HKLM\RX_SAM "$win\System32\config\SAM" 2>&1 | Out-String; W "load SAM: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SAM\SAM\Domains\Account\Users\Names') {
    Get-ChildItem 'HKLM:\RX_SAM\SAM\Domains\Account\Users\Names' -ErrorAction SilentlyContinue | ForEach-Object { W "  user: $($_.PSChildName)" }
} else { W "  no SAM Names key" }
$un = reg.exe unload HKLM\RX_SAM 2>&1 | Out-String; W "unload SAM: $($un.Trim())"

W "--- SYSTEM hive: Winmgmt / Schedule / 360 service Start values ---"
$ld = reg.exe load HKLM\RX_SYSTEM "$win\System32\config\SYSTEM" 2>&1 | Out-String; W "load SYSTEM: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SYSTEM') {
    foreach ($n in 'Winmgmt','Schedule','wuauserv','UsoSvc','360Antivirus','360safe','360rp','360AdvancedService','zhudongfangyu') {
        $key = "HKLM:\RX_SYSTEM\ControlSet001\Services\$n"
        if (Test-Path $key) {
            $p = Get-ItemProperty $key -ErrorAction SilentlyContinue
            W "  svc ${n}: Start=$($p.Start) Type=$($p.Type) ImagePath=$($p.ImagePath)"
        } else { W "  no svc key ${n}" }
    }
    W "--- Select ---"
    $sel = Get-ItemProperty 'HKLM:\RX_SYSTEM\Select' -ErrorAction SilentlyContinue
    W "  Select: Current=$($sel.Current) LastKnownGood=$($sel.LastKnownGood) Failed=$($sel.Failed)"
    $un = reg.exe unload HKLM\RX_SYSTEM 2>&1 | Out-String; W "unload SYSTEM: $($un.Trim())"
}

try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== sam done ==="
