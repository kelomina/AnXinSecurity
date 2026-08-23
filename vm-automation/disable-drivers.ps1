# Elevated: set Start=4 (disabled) for AnXin driver services in ALL control sets.
# Usage: disable-drivers.ps1 [startvalue]  (default 4 = disabled; pass 1 or 2 to re-enable)
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-disable-drivers.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== disable-drivers @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated"; exit 1 }

$svcStart = 4
if ($args.Count -gt 0) { $svcStart = [int]$args[0] }
W "target Start = $svcStart"

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
$cfg = "$letter`:\Windows\System32\config"
W "mount: $letter`:\"

$ld = reg.exe load HKLM\RX_SYSTEM "$cfg\SYSTEM" 2>&1 | Out-String; W "load SYSTEM: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SYSTEM') {
    $svcNames = 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService'
    foreach ($cs in 'ControlSet001','ControlSet002','CurrentControlSet') {
        W "--- $cs ---"
        foreach ($n in $svcNames) {
            $key = "HKLM:\RX_SYSTEM\$cs\Services\$n"
            if (Test-Path $key) {
                try { Set-ItemProperty -Path $key -Name 'Start' -Value $svcStart -ErrorAction Stop; W "set $n Start=$svcStart" } catch { W "fail ${n}: $($_.Exception.Message)" }
            } else { W "no key $n" }
        }
    }
    # also show the Select\Current value to know the active control set
    $sel = Get-ItemProperty 'HKLM:\RX_SYSTEM\Select' -ErrorAction SilentlyContinue
    W "Select: Current=$($sel.Current) LastKnownGood=$($sel.LastKnownGood) Failed=$($sel.Failed)"
    $un = reg.exe unload HKLM\RX_SYSTEM 2>&1 | Out-String; W "unload SYSTEM: $($un.Trim())"
} else { W "SYSTEM hive did not load" }

try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== disable-drivers done ==="
