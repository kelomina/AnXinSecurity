# offline-clean.ps1 — 从 Hyper-V 来宾 VHD 离线清除 AnXin 内核驱动
# Offline removal of AnXin kernel drivers from a Hyper-V guest VHD.
#
# 用法 / Usage (elevated / 需管理员):
#   powershell -ExecutionPolicy Bypass -File offline-clean.ps1 -VhdPath "D:\Virtual Hard Disks\xxx.avhdx"
#
# 做什么 / What it does:
#   1. 挂载 VHD，把系统分区挂到盘符 X  | Mount the VHD, assign X to the OS partition
#   2. 以 SYSTEM 计划任务加载 SYSTEM/SOFTWARE 蜂巢并删除 AnXin* 服务键（管理员被服务键 ACL 挡住，
#      无法离线删除；SYSTEM 上下文可绕过）| A SYSTEM scheduled task loads the SYSTEM/SOFTWARE hives and
#      deletes the AnXin* service keys (Administrators are ACL-blocked from deleting service keys;
#      SYSTEM context bypasses that).
#   3. 删除 System32\drivers 下的 AnXin*.sys | Delete AnXin*.sys from System32\drivers
#   4. 卸载蜂巢（此时 VHD 仍挂载，改动会 flush 回盘）| Unload the hives (VHD still mounted so changes flush)
#   5. 分离 VHD | Dismount the VHD
#
# 注意 / Notes:
#   - 必须先关机 VM，否则 VHD 被占用 | Stop the VM first, or the VHD is locked.
#   - 纯 ASCII（PS 5.1）| Pure ASCII.
#   - 会弹 UAC，需要人工批准 | Pops a UAC prompt for approval.

param(
    [Parameter(Mandatory=$true)][string]$VhdPath,
    [string[]]$ServiceNames = @(
        'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinHypervisor','AnXinSecurityService'
    ),
    [string[]]$DriverFiles = @(
        'AnXinProcProtect.sys','AnXinFileProtect.sys','AnXinNetFilter.sys','AnXinHypervisor.sys'
    ),
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-offline-clean.log',
    [string]$RxLogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-rx.log'
)

$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== offline-clean @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    W "ERROR: not elevated - run as administrator"; exit 1
}
if (-not (Test-Path $VhdPath)) { W "ERROR: VHD not found: $VhdPath"; exit 1 }

# --- mount ---
try { Mount-VHD -Path $VhdPath -NoDriveLetter -ErrorAction Stop; W "mounted: $([IO.Path]::GetFileName($VhdPath))" } catch { W "mount fail: $($_.Exception.Message)"; exit 1 }
Start-Sleep -Seconds 4

# identify the disk by a match token from the VHD filename (GUID if present)
$vhdBase = [IO.Path]::GetFileNameWithoutExtension($VhdPath)
$matchToken = $vhdBase
if ($vhdBase -match '([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})') { $matchToken = $matches[1] }
$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match [regex]::Escape($matchToken)) -or ($_.FriendlyName -match [regex]::Escape($matchToken)) -or ($_.Path -match [regex]::Escape($matchToken)) } | Select-Object -First 1
if (-not $disk) { W "ERROR: mounted disk not found (token=$matchToken)"; Dismount-VHD -Path $VhdPath -ErrorAction SilentlyContinue; exit 1 }
if ($disk.IsOffline) { try { Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop; W "brought online" } catch {} }

# OS partition (largest)
$part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 10GB } | Sort-Object Size -Descending | Select-Object -First 1
if (-not $part) { W "ERROR: no OS partition"; Dismount-VHD -Path $VhdPath -ErrorAction SilentlyContinue; exit 1 }
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

# --- build the SYSTEM-context helper cmd (deletes service keys, loads+unloads hives) ---
$sysHive = "$win\System32\config\SYSTEM"
$swHive  = "$win\System32\config\SOFTWARE"
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('@echo off')
$lines.Add("echo SYSTEM-task %date% %time% > `"$RxLogPath`"")
$lines.Add("echo hive-source=$sysHive >> `"$RxLogPath`"")
$lines.Add("reg load HKLM\RX_SYSTEM `"$sysHive`" >> `"$RxLogPath`" 2>&1")
foreach ($svc in $ServiceNames) {
    $lines.Add("reg delete HKLM\RX_SYSTEM\ControlSet001\Services\$svc /f >> `"$RxLogPath`" 2>&1")
    $lines.Add("reg delete HKLM\RX_SYSTEM\ControlSet002\Services\$svc /f >> `"$RxLogPath`" 2>&1")
}
$lines.Add("reg unload HKLM\RX_SYSTEM >> `"$RxLogPath`" 2>&1")
$lines.Add("reg load HKLM\RX_SOFTWARE `"$swHive`" >> `"$RxLogPath`" 2>&1")
$lines.Add("reg delete HKLM\RX_SOFTWARE\AnXinSecurity /f >> `"$RxLogPath`" 2>&1")
$lines.Add("reg unload HKLM\RX_SOFTWARE >> `"$RxLogPath`" 2>&1")
$lines.Add('echo DONE >> "' + $RxLogPath + '"')
$helperPath = 'C:\Windows\Temp\anxin-rx-helper.cmd'
Set-Content -Path $helperPath -Value ($lines -join "`r`n") -Encoding ascii
W "helper written"

# --- create + run the SYSTEM scheduled task ---
$tname = 'AnxinRxClean'
schtasks.exe /delete /tn $tname /f 2>&1 | Out-Null
$cr = schtasks.exe /create /tn $tname /tr "`"$helperPath`"" /sc once /st 23:59 /ru SYSTEM /f 2>&1 | Out-String
W "task create: $($cr.Trim())"
if (Test-Path $RxLogPath) { try { Remove-Item $RxLogPath -Force -ErrorAction SilentlyContinue } catch {} }
$rn = schtasks.exe /run /tn $tname 2>&1 | Out-String
W "task run: $($rn.Trim())"
$deadline = (Get-Date).AddSeconds(90); $done = $false
while ((Get-Date) -lt $deadline) {
    if (Test-Path $RxLogPath) {
        if (Select-String -Path $RxLogPath -Pattern 'DONE' -Quiet -ErrorAction SilentlyContinue) { $done = $true; W "SYSTEM task finished"; break }
    }
    Start-Sleep -Seconds 3
}
if (-not $done) { W "WARNING: SYSTEM task did not finish in 90s" }
schtasks.exe /delete /tn $tname /f 2>&1 | Out-Null
W "--- RX log ---"
if (Test-Path $RxLogPath) { Get-Content $RxLogPath | ForEach-Object { W "  $_" } } else { W "  no rx log" }

# --- delete driver files (files are NOT ACL-blocked) ---
$drv = Join-Path $win 'System32\drivers'
foreach ($f in $DriverFiles) {
    $p = Join-Path $drv $f
    if (Test-Path $p) {
        cmd /c "del /f /q `"$p`"" 2>&1 | Out-Null
        if (Test-Path $p) { W "STILL EXISTS $f" } else { W "DELETED $f" }
    } else { W "absent $f" }
}

try { Dismount-VHD -Path $VhdPath -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== offline-clean done ==="
