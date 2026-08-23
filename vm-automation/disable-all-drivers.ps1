# Elevated: mount the active snapshot-restored child, rename all AnXin*.sys out of
# System32\drivers (disables boot-time driver loading), and dump the ESP BCD.
# Recovery from "infinite automatic repair" after installing the driver bundle.
$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\anxin-disable-all.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== disable-all @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated"; exit 1 }

$child = Get-ChildItem 'D:\Virtual Hard Disks' -Filter '*6731AD29*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.avhdx' } | Select-Object -First 1
if (-not $child) { W "ERROR: active child not found"; exit 1 }
try { Mount-VHD -Path $child.FullName -NoDriveLetter -ErrorAction Stop; W "mounted: $($child.Name)" } catch { W "mount fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 4
$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match '6731AD29') -or ($_.FriendlyName -match '6731AD29') } | Select-Object -First 1
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
$drv = "$letter`:\Windows\System32\drivers"
W "mount: $letter`:\"

W "--- AnXin drivers present ---"
Get-ChildItem $drv -Filter 'AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { W "  $($_.Name) ($($_.Length) B) mod $($_.LastWriteTime.ToString('MM-dd HH:mm'))" }

foreach ($f in @('AnXinProcProtect.sys','AnXinFileProtect.sys','AnXinNetFilter.sys')) {
    $src = Join-Path $drv $f
    $dst = "$src.repair-disabled"
    if (Test-Path $src) {
        try { Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop; W "DISABLED: $f" } catch { W "disable fail $f: $($_.Exception.Message)" }
    } else { W "not present: $f" }
}
W "--- drivers folder after ---"
Get-ChildItem $drv -Filter 'AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { W "  $($_.Name)" }

# ESP + BCD
$espPart = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -lt 1GB -and $_.Type -match 'System' } | Sort-Object Size -Descending | Select-Object -First 1
if ($espPart) {
    if (-not $espPart.DriveLetter) {
        $used = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { $_.DriveLetter })
        $cand = @('Y','U','T','S') | Where-Object { $used -notcontains $_ } | Select-Object -First 1
        if ($cand) { try { Set-Partition -DiskNumber $disk.Number -PartitionNumber $espPart.PartitionNumber -NewDriveLetter $cand -ErrorAction Stop; W "esp -> $cand" } catch {} }
    }
    $espPart = Get-Partition -DiskNumber $disk.Number -PartitionNumber $espPart.PartitionNumber
    $esp = "$($espPart.DriveLetter):\"
    $bcd = "$esp`EFI\Microsoft\Boot\BCD"
    if (Test-Path $bcd) {
        W "--- BCD dump ---"
        $out = bcdedit.exe /store $bcd /enum 2>&1 | Out-String
        W $out.Trim()
    } else { W "BCD missing at $bcd" }
} else { W "no ESP partition" }

try { Dismount-VHD -Path $child.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== disable-all done ==="
