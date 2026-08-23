# deploy-fileprotect-instrumented.ps1
# Offline-deploy the VUL-097 instrumented AnXinFileProtect.sys into the VM's
# active differencing disk, so the instrumentation loads at next boot.
# PREREQ: VM must be OFF (avhdx must not be in use). Run elevated.
# All-ASCII.
param(
    [string]$NewSys = 'E:\Project\HTML\AnXinSecurity\native\file_protect\build\x64\Release\AnXinFileProtect.sys',
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-deploy-fp-instr.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== deploy-fp-instrumented @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    W "ERROR: not elevated"; exit 1
}
if (-not (Test-Path $NewSys)) { W "ERROR: new sys not found: $NewSys"; exit 1 }
W "new sys: $NewSys size=$((Get-Item $NewSys).Length)"

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Off') { W "ERROR: VM is $($vm.State); must be Off to mount avhdx"; exit 1 }

$avhdx = $vm.HardDrives | Where-Object { $_.Path -like '*.avhdx' } | Select-Object -First 1
if (-not $avhdx) { W "ERROR: no avhdx attached"; exit 1 }
$vhdPath = $avhdx.Path
W "attached avhdx: $vhdPath"
if (-not (Test-Path $vhdPath)) { W "ERROR: avhdx file missing"; exit 1 }

try { Mount-VHD -Path $vhdPath -NoDriveLetter -ErrorAction Stop; W "mounted" } catch { W "mount fail: $($_.Exception.Message)"; exit 1 }
Start-Sleep -Seconds 4

$disk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Location -match [regex]::Escape((Split-Path $vhdPath -Leaf).Split('_')[-1].Split('.')[0])) -or ($_.FriendlyName -match [regex]::Escape((Split-Path $vhdPath -Leaf).Split('_')[-1].Split('.')[0])) } | Select-Object -First 1
if (-not $disk) { W "ERROR: cannot locate mounted disk by unique id"; Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue; exit 1 }
if ($disk.IsOffline) { try { Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction Stop; W "brought online" } catch {} }

$part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Size -gt 10GB } | Sort-Object Size -Descending | Select-Object -First 1
if (-not $part) { W "ERROR: no big partition"; Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue; exit 1 }
if (-not $part.DriveLetter) {
    $used = @(Get-Volume | Where-Object DriveLetter | ForEach-Object { $_.DriveLetter })
    $cand = @('X','V','W','Z') | Where-Object { $used -notcontains $_ } | Select-Object -First 1
    if (-not $cand) { $cand = 'X' }
    try { Set-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -NewDriveLetter $cand -ErrorAction Stop; W "assigned $cand" } catch {}
}
$part = Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber
$letter = $part.DriveLetter
if (-not $letter) { W "ERROR: no letter"; Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue; exit 1 }
W "mount: $letter`:\"

$target = "$letter`:\Windows\System32\drivers\AnXinFileProtect.sys"
W "--- existing driver ---"
if (Test-Path $target) { W "existing: size=$((Get-Item $target).Length) modified=$((Get-Item $target).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" }
else { W "no existing AnXinFileProtect.sys at $target" }

try { Copy-Item $NewSys $target -Force -ErrorAction Stop; W "deployed: size=$((Get-Item $target).Length)" } catch { W "deploy fail: $($_.Exception.Message)" }

try { Dismount-VHD -Path $vhdPath -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== deploy-fp-instrumented done ==="
