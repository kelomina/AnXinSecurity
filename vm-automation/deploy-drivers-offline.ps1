# deploy-drivers-offline.ps1
# Offline-deploy both fixed drivers (AnXinFileProtect.sys + AnXinProcProtect.sys)
# into the VM's active differencing disk, so the fixes load at next boot.
# PREREQ: VM must be OFF (avhdx must not be in use). Run elevated.
# All-ASCII.
param(
    [string]$NewFileProtect = 'E:\Project\HTML\AnXinSecurity\native\file_protect\build\x64\Release\AnXinFileProtect.sys',
    [string]$NewProcProtect = 'E:\Project\HTML\AnXinSecurity\native\driver\build\x64\Release\AnXinProcProtect.sys',
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-deploy-drivers.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== deploy-drivers @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    W "ERROR: not elevated"; exit 1
}
foreach ($p in @($NewFileProtect, $NewProcProtect)) {
    if (-not (Test-Path $p)) { W "ERROR: new sys not found: $p"; exit 1 }
    W "new sys: $p size=$((Get-Item $p).Length)"
}

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

$targets = @(
    @{ Local = $NewFileProtect; Guest = "$letter`:\Windows\System32\drivers\AnXinFileProtect.sys"; Label = 'AnXinFileProtect.sys' },
    @{ Local = $NewProcProtect; Guest = "$letter`:\Windows\System32\drivers\AnXinProcProtect.sys"; Label = 'AnXinProcProtect.sys' }
)
foreach ($t in $targets) {
    W "--- $($t.Label) ---"
    if (Test-Path $t.Guest) { W "existing: size=$((Get-Item $t.Guest).Length) modified=$((Get-Item $t.Guest).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" }
    else { W "no existing $($t.Label) at $($t.Guest)" }
    try { Copy-Item $t.Local $t.Guest -Force -ErrorAction Stop; W "deployed: size=$((Get-Item $t.Guest).Length)" } catch { W "deploy fail: $($_.Exception.Message)" }
}

try { Dismount-VHD -Path $vhdPath -ErrorAction Stop; W "dismounted" } catch { W "dismount fail: $($_.Exception.Message)" }
W "=== deploy-drivers done ==="
