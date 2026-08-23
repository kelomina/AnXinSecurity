# antagonist-restore-cp.ps1 - restore a VM checkpoint, start VM, wait for PS Direct.
param(
    [Parameter(Mandatory=$true)][string]$CheckpointName,
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== restore-cp @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Off') { Stop-VM -VM $vm -Force; W "VM stopped" }
Start-Sleep -Seconds 6
$cp = Get-VMCheckpoint -VM $vm -Name $CheckpointName -ErrorAction SilentlyContinue
if (-not $cp) { W "ERROR: checkpoint '$CheckpointName' not found"; exit 1 }
Restore-VMCheckpoint -VM $vm -Name $CheckpointName -Confirm:$false
W "restored: $CheckpointName"
Start-VM -VM $vm
W "VM started"
Start-Sleep -Seconds 40

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(180); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 3
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$r = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    foreach ($svc in 'AnXinSecurityService','AnXinProcProtect','AnXinFileProtect','AnXinProcMon') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $out += "$svc = $(if ($q -match 'RUNNING') {'RUNNING'} else {'NOT-RUNNING'})"
    }
    $exe = Get-Item 'C:\Program Files\AnXinSecurity\anxin-security.exe' -ErrorAction SilentlyContinue
    if ($exe) { $out += "exe bytes=$($exe.Length) modified=$($exe.LastWriteTime)" }
    $rp = 'C:\Program Files\AnXinSecurity\config\etw_match_rules.json'
    if (Test-Path $rp) {
        $raw = [System.IO.File]::ReadAllText($rp, (New-Object System.Text.UTF8Encoding($false)))
        $arr = $raw | ConvertFrom-Json
        $out += "rules=$($arr.Count)"
    } else { $out += "NO rules file" }
    try { $p = Get-MpPreference; $out += "Defender exclusions=$($p.ExclusionPath -join ';')" } catch {}
    try { $cs = Get-MpComputerStatus; $out += "RealTimeProtectionEnabled=$($cs.RealTimeProtectionEnabled)" } catch {}
    ,$out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== restore-cp done ==="