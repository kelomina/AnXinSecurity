# Elevated: mount broken child, verify boot files (winload.efi, bootmgfw.efi,
# bootx64.efi) and dump the ESP's BCD to diagnose 0xc000000e.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-bootcheck.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== bootcheck @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated"; exit 1 }

$broken = Get-ChildItem 'D:\Virtual Hard Disks' -Filter '*31EECB48*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.avhdx' } | Select-Object -First 1
if (-not $broken) { W "ERROR: broken child not found"; exit 1 }
try { Mount-VHD -Path $broken.FullName -NoDriveLetter -ErrorAction Stop; W "mounted" } catch { W "mount fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 4
$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match '31EECB48') -or ($_.FriendlyName -match '31EECB48') } | Select-Object -First 1
if (-not $disk) { W "ERROR: disk not found"; exit 1 }
if ($disk.IsOffline) { try { Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop; W "brought online" } catch {} }
Start-Sleep -Seconds 2

W "--- partitions ---"
Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | ForEach-Object { W "  part$($_.PartitionNumber): size=$($_.Size) type=$($_.Type) letter=$($_.DriveLetter) fs=$((Get-Volume -Partition $_ -ErrorAction SilentlyContinue).FileSystem)" }

# assign letters: OS (big) -> X, ESP (System, FAT32, small) -> Y
$used = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { $_.DriveLetter })
$cand = @('X','V','W','Z') | Where-Object { $used -notcontains $_ }
$osLetter = $cand[0]
$espLetter = $cand[1]

$parts = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)
$osPart = $parts | Where-Object { $_.Size -gt 10GB } | Sort-Object Size -Descending | Select-Object -First 1
$espPart = $parts | Where-Object { $_.Size -lt 1GB -and ($_.Type -match 'System') } | Sort-Object Size -Descending | Select-Object -First 1
if (-not $espPart) { $espPart = $parts | Where-Object { $_.Size -lt 1GB -and $_.Size -gt 10MB } | Sort-Object Size -Descending | Select-Object -First 1 }

if ($osPart) {
    if (-not $osPart.DriveLetter) { try { Set-Partition -DiskNumber $disk.Number -PartitionNumber $osPart.PartitionNumber -NewDriveLetter $osLetter -ErrorAction Stop; W "os -> $osLetter" } catch { W "os letter fail: $($_.Exception.Message)" } }
    else { $osLetter = $osPart.DriveLetter }
} else { W "ERROR: no OS partition"; exit 1 }
if ($espPart) {
    if (-not $espPart.DriveLetter) { try { Set-Partition -DiskNumber $disk.Number -PartitionNumber $espPart.PartitionNumber -NewDriveLetter $espLetter -ErrorAction Stop; W "esp -> $espLetter" } catch { W "esp letter fail: $($_.Exception.Message)" } }
    else { $espLetter = $espPart.DriveLetter }
} else { W "no ESP partition found" }

$osRoot = "$osLetter`:\"
$espRoot = "$espLetter`:\"
W "--- OS volume boot files ---"
foreach ($f in @("$osRoot`Windows\System32\winload.efi", "$osRoot`Windows\System32\winload.exe", "$osRoot`Windows\System32\boot\winload.efi")) {
    if (Test-Path $f) { $fi = Get-Item $f; W "  OK: $f ($($fi.Length) B)" } else { W "  MISSING: $f" }
}
W "--- ESP contents ---"
if ($espPart) {
    foreach ($f in @("$espRoot`EFI\Microsoft\Boot\bootmgfw.efi", "$espRoot`EFI\BOOT\bootx64.efi", "$espRoot`EFI\Microsoft\Boot\BCD", "$espRoot`EFI\Microsoft\Boot\boot.stl")) {
        if (Test-Path $f) { $fi = Get-Item $f; W "  OK: $f ($($fi.Length) B)" } else { W "  MISSING: $f" }
    }
    W "--- ESP EFI dir tree ---"
    if (Test-Path "$espRoot`EFI") { Get-ChildItem "$espRoot`EFI" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 30 | ForEach-Object { W "  esp: $($_.FullName.Substring($espRoot.Length))" } }
    else { W "  no EFI dir on ESP" }
    W "--- BCD dump ---"
    $bcd = "$espRoot`EFI\Microsoft\Boot\BCD"
    if (Test-Path $bcd) {
        $out = bcdedit.exe /store $bcd /enum 2>&1 | Out-String
        W $out.Trim()
    } else { W "  BCD missing" }
} else { W "no ESP to inspect" }

try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== bootcheck done ==="
