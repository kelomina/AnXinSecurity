# Elevated: offline cleanup of old AnXin kernel drivers from the 病毒测试 guest VHD.
# v9 (2026-08-13): v7/v8 proved in-memory hive edits do NOT survive a dismount/re-mount
#   cycle (RX_SYSTEM5 reload after the SYSTEM unload still showed all 3 keys on disk).
#   v9 does everything in ONE continuous session with the disk mounted throughout:
#   fresh-load RX_SYSTEM6 -> ONE SYSTEM task deletes the 3 keys THEN unloads the hive
#   (flush while mounted) -> reload RX_SYSTEM7 to VERIFY persistence -> SYSTEM-unload
#   RX_SYSTEM7 -> dismount only at the very end. Pure ASCII.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-offline-clean.log'
$rxlog = 'C:\Users\Saika\AppData\Local\Temp\anxin-rx6.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== offline-clean v9 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated"; exit 1 }

# 1. mount the VM's current boot disk
$vm = Get-VM -Id '7b66415c-52cb-468e-b9bd-368746f42863' -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
$diskPath = $vm.HardDrives | Select-Object -First 1 -ExpandProperty Path
if (-not $diskPath -or -not (Test-Path $diskPath)) { W "ERROR: no VM disk at $diskPath"; exit 1 }
$child = Get-Item $diskPath
try { Mount-VHD -Path $child.FullName -NoDriveLetter -ErrorAction Stop; W "mounted: $($child.Name)" } catch { W "mount fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 4
$diskGuid = [regex]::Match($child.BaseName, '[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}').Value
if (-not $diskGuid) { $diskGuid = $child.BaseName }
$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match [regex]::Escape($diskGuid)) -or ($_.FriendlyName -match [regex]::Escape($diskGuid)) } | Select-Object -First 1
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
$hiveSys = Join-Path $win 'System32\config\SYSTEM'
W "mount: $letter`:\"

# 1b. clean up any dangling hives from earlier runs (SYSTEM unload)
foreach ($h in 'RX_SYSTEM','RX_SYSTEM2','RX_SYSTEM3','RX_SYSTEM5') {
    if (Test-Path "HKLM:\$h") {
        reg.exe unload "HKLM\$h" 2>&1 | Out-Null
        W "cleanup unload ${h}: loaded=$([bool](Test-Path "HKLM:\$h"))"
    }
}

# 2. fresh load RX_SYSTEM6 (this is the hive we edit + unload, all while mounted)
$ld = reg.exe load HKLM\RX_SYSTEM6 "$hiveSys" 2>&1 | Out-String; W "load RX_SYSTEM6: $($ld.Trim())"
if (-not (Test-Path 'HKLM:\RX_SYSTEM6')) { W "ERROR: RX_SYSTEM6 did not load"; exit 1 }

# 3. ONE SYSTEM task: delete the 3 service keys, then unload RX_SYSTEM6 (flush while mounted)
$helper = @'
@echo off
set "RXLOCAL=C:\Users\Saika\AppData\Local\Temp\anxin-rx6.log"
echo SYSTEM-delete-unload %date% %time% > "%RXLOCAL%"
reg delete HKLM\RX_SYSTEM6\ControlSet001\Services\AnXinProcProtect /f >> "%RXLOCAL%" 2>&1
reg delete HKLM\RX_SYSTEM6\ControlSet001\Services\AnXinFileProtect /f >> "%RXLOCAL%" 2>&1
reg delete HKLM\RX_SYSTEM6\ControlSet001\Services\AnXinNetFilter /f >> "%RXLOCAL%" 2>&1
echo DELETED >> "%RXLOCAL%"
reg unload HKLM\RX_SYSTEM6 >> "%RXLOCAL%" 2>&1
echo DONE >> "%RXLOCAL%"
'@
$helperPath = 'C:\Windows\Temp\anxin-rx6-helper.cmd'
Set-Content -Path $helperPath -Value $helper -Encoding ascii
W "helper written"
$tname = 'AnXinRxClean6'
schtasks.exe /delete /tn $tname /f 2>&1 | Out-Null
$cr = schtasks.exe /create /tn $tname /tr "`"$helperPath`"" /sc once /st 23:59 /ru SYSTEM /f 2>&1 | Out-String
W "task create: $($cr.Trim())"
if (Test-Path $rxlog) { Remove-Item $rxlog -Force -ErrorAction SilentlyContinue }
$rn = schtasks.exe /run /tn $tname 2>&1 | Out-String
W "task run: $($rn.Trim())"
$deadline = (Get-Date).AddSeconds(90); $done = $false
while ((Get-Date) -lt $deadline) {
    if (Test-Path $rxlog) { if (Select-String -Path $rxlog -Pattern 'DONE' -Quiet -ErrorAction SilentlyContinue) { $done = $true; break } }
    Start-Sleep -Seconds 3
}
if (-not $done) { W "WARNING: task did not finish in 90s" }
schtasks.exe /delete /tn $tname /f 2>&1 | Out-Null
W "--- RX6 log ---"
if (Test-Path $rxlog) { Get-Content $rxlog | ForEach-Object { W "  $_" } } else { W "  no rx6 log" }
Start-Sleep -Seconds 5
W "RX_SYSTEM6 loaded after task: $([bool](Test-Path 'HKLM:\RX_SYSTEM6'))"

# 4. VERIFY persistence: fresh-load RX_SYSTEM7 from disk and confirm the keys are gone
$ld = reg.exe load HKLM\RX_SYSTEM7 "$hiveSys" 2>&1 | Out-String; W "reload RX_SYSTEM7 (persistence check): $($ld.Trim())"
if (Test-Path 'HKLM:\RX_SYSTEM7') {
    $chk = Get-ChildItem 'HKLM:\RX_SYSTEM7\ControlSet001\Services','HKLM:\RX_SYSTEM7\ControlSet002\Services' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'anxin' } | ForEach-Object { $_.PSChildName }
    if ($chk) {
        W "PERSISTENCE-FAIL: disk still has: $([string]::Join(',', @($chk)))"
    } else {
        W "PERSISTENCE-OK: fresh disk load has no AnXin service keys"
    }
} else { W "ERROR: RX_SYSTEM7 did not load" }

# 5. SYSTEM-unload RX_SYSTEM7 (reg unload in this process fails on these hives)
if (Test-Path 'HKLM:\RX_SYSTEM7') {
    $h7 = @'
@echo off
reg unload HKLM\RX_SYSTEM7
'@
    $h7Path = 'C:\Windows\Temp\anxin-rx7-unload.cmd'
    Set-Content -Path $h7Path -Value $h7 -Encoding ascii
    $t7 = 'AnXinRxUnload7'
    schtasks.exe /delete /tn $t7 /f 2>&1 | Out-Null
    schtasks.exe /create /tn $t7 /tr "`"$h7Path`"" /sc once /st 23:59 /ru SYSTEM /f 2>&1 | Out-Null
    schtasks.exe /run /tn $t7 2>&1 | Out-Null
    Start-Sleep -Seconds 8
    schtasks.exe /delete /tn $t7 /f 2>&1 | Out-Null
    W "RX_SYSTEM7 loaded after SYSTEM unload: $([bool](Test-Path 'HKLM:\RX_SYSTEM7'))"
}

# 6. driver files + app dir (idempotent)
$drv = Join-Path $win 'System32\drivers'
foreach ($f in 'AnXinProcProtect.sys','AnXinFileProtect.sys','AnXinNetFilter.sys','AnXinHypervisor.sys') {
    $p = Join-Path $drv $f
    if (Test-Path $p) {
        cmd /c "del /f /q `"$p`"" 2>&1 | Out-Null
        if (Test-Path $p) { W "STILL EXISTS $f" } else { W "DELETED $f" }
    } else { W "absent $f" }
}
$appDir = "$letter`:\Program Files\AnXinSecurity"
if (Test-Path $appDir) {
    cmd /c "rd /s /q `"$appDir`"" 2>&1 | Out-Null
    if (Test-Path $appDir) { W "STILL EXISTS app dir" } else { W "DELETED app dir" }
} else { W "app dir absent" }

try { Dismount-VHD -Path $child.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== offline-clean v9 done ==="
