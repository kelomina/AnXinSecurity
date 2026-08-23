# Elevated: mount broken child, deploy the newly built AnXinProcProtect.sys, set DiagFlags, dismount.
# Usage: deploy-driver.ps1 [path-to-new-sys] [DiagFlags]
#   DiagFlags: 0 = full protection (default), 12 = ObCallbacks disabled
# All-ASCII.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-deploy-driver.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== deploy-driver @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    W "ERROR: not elevated"; exit 1
}

$newSys = 'E:\Project\HTML\AnXinSecurity\native\driver\build\x64\Release\AnXinProcProtect.sys'
if ($args.Count -gt 0) { $newSys = $args[0] }
$flags = 0
if ($args.Count -gt 1) { $flags = [int]$args[1] }
if (-not (Test-Path $newSys)) { W "ERROR: new sys not found: $newSys"; exit 1 }
W "new sys: $newSys (size=$((Get-Item $newSys).Length))"
W "target DiagFlags: $flags"

$broken = Get-ChildItem 'D:\Virtual Hard Disks' -Filter '*31EECB48*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.avhdx' } | Select-Object -First 1
if (-not $broken) { W "ERROR: broken child not found"; exit 1 }

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

$driversDir = "$letter`:\Windows\System32\drivers"
W "--- existing anxin driver files ---"
Get-ChildItem $driversDir -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'anxin|AnXin' } | ForEach-Object { W "driver file: $($_.Name) size=$($_.Length) modified=$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" }

$target = "$driversDir\AnXinProcProtect.sys"
$existed = Test-Path $target
if ($existed) {
    # back up the old driver so we can roll back
    try { Copy-Item $target "$target.bak" -Force -ErrorAction Stop; W "backed up old driver to .bak" } catch { W "backup fail: $($_.Exception.Message)" }
}
try {
    Copy-Item $newSys $target -Force -ErrorAction Stop
    W "deployed new driver: $target size=$((Get-Item $target).Length)"
} catch { W "deploy fail: $($_.Exception.Message)" }

# set DiagFlags in SOFTWARE hive
$cfg = "$letter`:\Windows\System32\config"
$ld = reg.exe load HKLM\RX_SOFTWARE "$cfg\SOFTWARE" 2>&1 | Out-String; W "load SOFTWARE: $($ld.Trim())"
try {
    $p = 'HKLM:\RX_SOFTWARE\AnXinSecurity'
    New-Item -Path $p -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $p -Name 'DiagFlags' -Value $flags -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    W "DiagFlags set = $((Get-ItemProperty $p).DiagFlags)"
} catch { W "DiagFlags fail: $($_.Exception.Message)" }
$un = reg.exe unload HKLM\RX_SOFTWARE 2>&1 | Out-String; W "unload SOFTWARE: $($un.Trim())"

W "--- verify driver + service keys ---"
$ld = reg.exe load HKLM\RX_SYSTEM "$cfg\SYSTEM" 2>&1 | Out-String; W "load SYSTEM: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SYSTEM') {
    foreach ($cs in 'ControlSet001','ControlSet002','CurrentControlSet') {
        Get-ChildItem "HKLM:\RX_SYSTEM\$cs\Services" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'anxin' } | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            W "$cs svc: $($_.PSChildName) Start=$($p.Start) ImagePath=$($p.ImagePath)"
        }
    }
    $un = reg.exe unload HKLM\RX_SYSTEM 2>&1 | Out-String; W "unload SYSTEM: $($un.Trim())"
} else { W "SYSTEM hive did not load" }

try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== deploy-driver done ==="
