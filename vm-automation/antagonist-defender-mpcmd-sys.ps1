# antagonist-defender-mpcmd-sys.ps1 - run MpCmdRun -RemoveDefinitions -All as SYSTEM
# via scheduled task (MpCmdRun needs SYSTEM to mutate signature store).
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== defender-mpcmd-sys @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
$log = 'C:\Windows\Temp\anxin-defender-mpcmd-sys.log'
"mpcmd-sys @ $(Get-Date -Format 'HH:mm:ss')" | Add-Content $log
$mp = (Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe' | Sort-Object FullName -Descending | Select-Object -First 1).FullName
"mp=$mp" | Add-Content $log
$r = & $mp -RemoveDefinitions -All 2>&1 | Out-String
"result: $r" | Add-Content $log
"done" | Add-Content $log
'@
$sysPath = 'C:\Windows\Temp\anxin-defender-mpcmd-sys.ps1'
Invoke-Command -Session $s -ScriptBlock { param($p,$c) [System.IO.File]::WriteAllText($p,$c,(New-Object System.Text.UTF8Encoding($false))) } -ArgumentList $sysPath, $sysScript

$r = Invoke-Command -Session $s -ScriptBlock {
    param($scriptPath)
    $out = @()
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinMpCmdSys' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinMpCmdSys'
    Start-Sleep -Seconds 20
    $ti = Get-ScheduledTaskInfo -TaskName 'AnXinMpCmdSys' -ErrorAction SilentlyContinue
    if ($ti) { $out += "task LastTaskResult=$($ti.LastTaskResult)" }
    Unregister-ScheduledTask -TaskName 'AnXinMpCmdSys' -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path 'C:\Windows\Temp\anxin-defender-mpcmd-sys.log') { $out += Get-Content 'C:\Windows\Temp\anxin-defender-mpcmd-sys.log' }
    ,$out
} -ArgumentList $sysPath
$r | ForEach-Object { W "  $_" }

Remove-PSSession $s
W "=== defender-mpcmd-sys done ==="