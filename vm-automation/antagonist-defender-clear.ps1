# antagonist-defender-clear.ps1 - remove Defender threat detections (as SYSTEM)
# and verify realtime state, so already-flagged samples can be launched.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== defender-clear @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }
W "PS Direct connected"

$sysScript = @'
$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\anxin-defender-clear.log'
"defender-clear @ $(Get-Date -Format 'HH:mm:ss')" | Add-Content $log
# remove all threat detections
Get-MpThreatDetection | ForEach-Object { Remove-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue }
"threat detections removed: $((Get-MpThreatDetection | Measure-Object).Count) remaining" | Add-Content $log
# force a quick signature/state refresh
Update-MpSignature -ErrorAction SilentlyContinue | Out-Null
"signature refresh attempted" | Add-Content $log
'@
$sysPath = 'C:\Windows\Temp\anxin-defender-clear.ps1'
Invoke-Command -Session $s -ScriptBlock { param($p,$c) [System.IO.File]::WriteAllText($p,$c,(New-Object System.Text.UTF8Encoding($false))) } -ArgumentList $sysPath, $sysScript

$r = Invoke-Command -Session $s -ScriptBlock {
    param($scriptPath)
    $out = @()
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinClearDefender' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinClearDefender'
    Start-Sleep -Seconds 15
    Unregister-ScheduledTask -TaskName 'AnXinClearDefender' -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path 'C:\Windows\Temp\anxin-defender-clear.log') { $out += Get-Content 'C:\Windows\Temp\anxin-defender-clear.log' }
    $det = Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object
    $out += "remaining detections: $($det.Count)"
    ,$out
} -ArgumentList $sysPath
$r | ForEach-Object { W "  $_" }
Remove-PSSession $s
W "=== defender-clear done ==="