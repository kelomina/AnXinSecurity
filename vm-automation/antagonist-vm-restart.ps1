# antagonist-vm-restart.ps1 - restart the VM (graceful shutdown) and wait for it to come back.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== vm-restart @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }

# graceful shutdown if running
if ($vm.State -eq 'Running') {
    Stop-VM -VM $vm -Force
    W "VM stopped"
    Start-Sleep -Seconds 8
}
Start-VM -VM $vm
W "VM started, waiting for boot..."
Start-Sleep -Seconds 45

# wait for PS Direct
$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(180); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 3
}
if (-not $s) { W "ERROR: PS Direct connect failed after restart"; exit 1 }
W "PS Direct connected"
Remove-PSSession $s
W "=== vm-restart done ==="