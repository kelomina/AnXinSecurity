# Elevated: mount broken child, rename AnXinProcProtect.sys out of the drivers
# folder so the boot-start service cannot load it. Reverse with arg "restore".
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-driverfile.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== driverfile @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated"; exit 1 }

$do = 'disable'
if ($args.Count -gt 0) { $do = $args[0] }
W "action = $do"

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
$sys = "$letter`:\Windows\System32\drivers\AnXinProcProtect.sys"
W "mount: $letter`:\"

if (Test-Path $sys) {
    $f = Get-Item $sys
    W "driver file present: $($f.Length) bytes, modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    $target = "$sys.disabled"
    if ($do -eq 'restore') {
        if (Test-Path $target) { try { Move-Item -LiteralPath $target -Destination $sys -Force -ErrorAction Stop; W "RESTORED" } catch { W "restore fail: $($_.Exception.Message)" } }
        else { W "no .disabled file to restore" }
    } else {
        try { Move-Item -LiteralPath $sys -Destination $target -Force -ErrorAction Stop; W "DISABLED -> AnXinProcProtect.sys.disabled" } catch { W "disable fail: $($_.Exception.Message)" }
    }
    W "driver folder now:"
    Get-ChildItem "$letter`:\Windows\System32\drivers" -Filter 'AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { W "  $($_.Name) ($($_.Length) B)" }
} else { W "driver file NOT present" }

try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== driverfile done ==="
