# restore-and-install.ps1 - restore the clean pre-install checkpoint, start the
# guest, then run the NSIS installer. Host-side.
param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [string]$CheckpointName = 'CleanBaseline-PreDriverInstall_20260813_0150',
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-restore-install.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== restore-and-install @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath
if (-not (Test-Path $InstallerPath)) { W "ERROR: installer not found: $InstallerPath"; exit 1 }

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM $VmId not found"; exit 1 }
if ($vm.State -ne 'Off') { Stop-VM -VM $vm -Force -ErrorAction SilentlyContinue; W "VM stopped (was $($vm.State))" }
Start-Sleep -Seconds 5

$cp = Get-VMCheckpoint -VM $vm -Name $CheckpointName -ErrorAction SilentlyContinue
if (-not $cp) { W "ERROR: checkpoint '$CheckpointName' not found"; exit 1 }
Restore-VMCheckpoint -VM $vm -Name $CheckpointName -Confirm:$false
W "checkpoint restored: $CheckpointName"
Start-VM -VM $vm
W "VM started"

W "=== restore-and-install done, run install-test next ==="
