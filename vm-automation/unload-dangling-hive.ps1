# Elevated: unload any dangling RX_* host hives left over from offline-clean runs.
# v9's in-process SYSTEM-task unload of RX_SYSTEM7 failed (same-process handle theory),
# so run it from a FRESH elevated process that never loaded the hive. Mounts the guest
# disk (so the backing SYSTEM file is reachable for the flush), lets a SYSTEM task unload
# every loaded RX_* hive, verifies, then dismounts. Pure ASCII.
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-unload.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== unload-dangling @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { W "ERROR: not elevated"; exit 1 }

# 0. identify loaded hives up front (before touching the disk)
$hives = @()
foreach ($h in 'RX_SYSTEM','RX_SYSTEM2','RX_SYSTEM3','RX_SYSTEM5','RX_SYSTEM6','RX_SYSTEM7') {
    if (Test-Path "HKLM:\$h") { $hives += $h }
}
if ($hives.Count -eq 0) { W "no dangling hives; nothing to do"; exit 0 }
W "loaded hives: $([string]::Join(',', $hives))"

# 1. mount the VM's current boot disk (needed so unload can flush to the backing file)
$vm = Get-VM -Id '7b66415c-52cb-468e-b9bd-368746f42863' -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
$diskPath = $vm.HardDrives | Select-Object -First 1 -ExpandProperty Path
if (-not $diskPath -or -not (Test-Path $diskPath)) { W "ERROR: no VM disk at $diskPath"; exit 1 }
$child = Get-Item $diskPath
try { Mount-VHD -Path $child.FullName -NoDriveLetter -ErrorAction Stop; W "mounted: $($child.Name)" } catch { W "mount fail: $($_.Exception.Message)" }
Start-Sleep -Seconds 4

# 2. SYSTEM task unloads every loaded hive (SYSTEM bypasses deny ACLs; fresh process)
$unloads = $hives | ForEach-Object { "reg unload HKLM\$_ >> `"%RXLOCAL%`" 2>&1" }
$helper = @"
@echo off
set "RXLOCAL=C:\Users\Saika\AppData\Local\Temp\anxin-unload-task.log"
echo unload-task %date% %time% > "%RXLOCAL%"
$($unloads -join "`r`n")
echo DONE >> "%RXLOCAL%"
"@
$helperPath = 'C:\Windows\Temp\anxin-unload-helper.cmd'
Set-Content -Path $helperPath -Value $helper -Encoding ascii
W "helper written"
$tname = 'AnXinDanglingUnload'
schtasks.exe /delete /tn $tname /f 2>&1 | Out-Null
$cr = schtasks.exe /create /tn $tname /tr "`"$helperPath`"" /sc once /st 23:59 /ru SYSTEM /f 2>&1 | Out-String
W "task create: $($cr.Trim())"
$rlog = 'C:\Users\Saika\AppData\Local\Temp\anxin-unload-task.log'
if (Test-Path $rlog) { Remove-Item $rlog -Force -ErrorAction SilentlyContinue }
schtasks.exe /run /tn $tname 2>&1 | Out-Null
$deadline = (Get-Date).AddSeconds(60); $done = $false
while ((Get-Date) -lt $deadline) {
    if (Test-Path $rlog) { if (Select-String -Path $rlog -Pattern 'DONE' -Quiet -ErrorAction SilentlyContinue) { $done = $true; break } }
    Start-Sleep -Seconds 3
}
if (-not $done) { W "WARNING: task did not finish in 60s" }
schtasks.exe /delete /tn $tname /f 2>&1 | Out-Null
Start-Sleep -Seconds 5
W "--- unload task log ---"
if (Test-Path $rlog) { Get-Content $rlog | ForEach-Object { W "  $_" } } else { W "  no task log" }

# 3. verify
foreach ($h in $hives) { W "${h}: loaded=$([bool](Test-Path "HKLM:\$h"))" }

try { Dismount-VHD -Path $child.FullName -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== unload-dangling done ==="
