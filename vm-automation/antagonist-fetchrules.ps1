# antagonist-fetchrules.ps1 - copy the deployed rule files + evidence out of the
# VM for host-side inspection.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$OutDir = 'E:\Project\HTML\AnXinSecurity\vm-automation\output',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-fetch.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== antagonist-fetchrules @ $(Get-Date -Format 'HH:mm:ss') ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if ($vm.State -ne 'Running') { Start-VM -VM $vm; Start-Sleep -Seconds 20 }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
foreach ($pair in @(
    @('C:\Program Files\AnXinSecurity\config\etw_match_rules.json', 'vm_deployed_rules.json'),
    @('C:\Program Files\AnXinSecurity\_up_\config\etw_match_rules.json', 'vm_up_rules.json'),
    @('C:\Windows\Temp\etw_match_rules_backup.json', 'vm_backup_rules.json')
)) {
    $p = $pair[0]; $d = Join-Path $OutDir $pair[1]
    try {
        Copy-Item -FromSession $s -Path $p -Destination $d -Force
        W "copied: $p -> $d"
    } catch { W "copy failed: $p ($($_.Exception.Message))" }
}
Remove-PSSession $s
W "=== fetch done ==="
