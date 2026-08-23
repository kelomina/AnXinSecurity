# Elevated: mount broken child, dump recent Application.evtx + today's System.evtx
# shutdown/crash events, check GroupPolicy scripts / Startup folders / BootExecute.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-applog.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== applog @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

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

$evtx = "$win\System32\winevt\Logs"

W "--- Application.evtx: last 20 events ---"
$app = "$evtx\Application.evtx"
if (Test-Path $app) {
    $evts = Get-WinEvent -Path $app -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($evts) { $evts | ForEach-Object { W "[$($_.TimeCreated.ToString('MM-dd HH:mm:ss'))] src=$($_.ProviderName) id=$($_.Id): $($_.Message.Split("`n")[0])" } }
    else { W "no Application events readable" }
} else { W "no Application.evtx" }

W "--- System.evtx: 1074/1001/41/6008 events (most recent 12) ---"
$sys = "$evtx\System.evtx"
if (Test-Path $sys) {
    $evts = Get-WinEvent -Path $sys -FilterXPath "*[System[(EventID=1074 or EventID=1001 or EventID=41 or EventID=6008)]]" -MaxEvents 12 -ErrorAction SilentlyContinue
    if ($evts) { $evts | ForEach-Object { W "[$($_.TimeCreated.ToString('MM-dd HH:mm:ss'))] id=$($_.Id): $($_.Message.Split("`n")[0])" } }
    else { W "none found" }
}

W "--- System.evtx: events around 16:2x today (last 25 regardless of id) ---"
if (Test-Path $sys) {
    $evts = Get-WinEvent -Path $sys -MaxEvents 25 -ErrorAction SilentlyContinue
    if ($evts) { $evts | ForEach-Object { W "[$($_.TimeCreated.ToString('MM-dd HH:mm:ss'))] src=$($_.ProviderName) id=$($_.Id): $($_.Message.Split("`n")[0])" } }
}

W "--- GroupPolicy machine scripts ---"
$gp = "$win\System32\GroupPolicy\Machine\Scripts"
if (Test-Path $gp) { Get-ChildItem $gp -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { W "  GP: $($_.FullName.Substring($gp.Length))" } } else { W "  no GP scripts dir" }

W "--- Startup folders ---"
foreach ($s in @("$win\..\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$win\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")) {
    if (Test-Path $s) { Get-ChildItem $s -Force -ErrorAction SilentlyContinue | ForEach-Object { W "  startup: $($_.Name)" } } else { W "  no startup dir: $s" }
}

W "--- legacy Tasks dir (C:\Windows\Tasks) ---"
$lt = "$win\Tasks"
if (Test-Path $lt) { Get-ChildItem $lt -Force -ErrorAction SilentlyContinue | ForEach-Object { W "  task: $($_.Name)" } } else { W "  no legacy Tasks dir" }

W "--- BootExecute (Session Manager) ---"
$ld = reg.exe load HKLM\RX_SYSTEM "$win\System32\config\SYSTEM" 2>&1 | Out-String; W "load SYSTEM: $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SYSTEM') {
    $be = Get-ItemProperty 'HKLM:\RX_SYSTEM\ControlSet001\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue
    if ($be) { W "  BootExecute = $($be.BootExecute)" } else { W "  no BootExecute" }
    $un = reg.exe unload HKLM\RX_SYSTEM 2>&1 | Out-String; W "unload SYSTEM: $($un.Trim())"
}

try { Dismount-VHD -Path $broken.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== applog done ==="
