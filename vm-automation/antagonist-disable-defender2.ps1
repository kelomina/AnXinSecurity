# antagonist-disable-defender2.ps1 - disable Defender realtime protection via
# group-policy registry (bypasses tamper protection) using a SYSTEM scheduled task,
# then also apply path/process exclusions. Verify result.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== disable-defender2 @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }
W "PS Direct connected"

# Run as SYSTEM: write group policy keys to fully disable Defender.
$sysScript = @'
$ErrorActionPreference = 'Continue'
$log = 'C:\Windows\Temp\anxin-defender2.log'
"defender2 @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content $log
$keys = @{
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' = @{
    'DisableAntiSpyware' = 1
    'DisableAntiVirus' = 1
  }
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' = @{
    'DisableRealtimeMonitoring' = 1
    'DisableIOAVProtection' = 1
    'DisableBehaviorMonitoring' = 1
    'DisableOnAccessProtection' = 1
    'DisableScanOnRealtimeEnable' = 1
  }
}
foreach ($k in $keys.Keys) {
    New-Item -Path $k -Force -ErrorAction SilentlyContinue | Out-Null
    foreach ($name in $keys[$k].Keys) {
        Set-ItemProperty -Path $k -Name $name -Value $keys[$k][$name] -Type DWord -Force
        "set $k\$name=$($keys[$k][$name])" | Add-Content $log
    }
}
# also add exclusions via policy (path + extensions + process)
$pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
New-Item -Path "$pol\Paths" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "$pol\Paths" -Name 'C:\Samples' -Value 0 -Type DWord -Force
New-Item -Path "$pol\Extensions" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "$pol\Extensions" -Name 'exe' -Value 0 -Type DWord -Force
New-Item -Path "$pol\Processes" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "$pol\Processes" -Name 'wscript.exe' -Value 0 -Type DWord -Force
Set-ItemProperty -Path "$pol\Processes" -Name 'cscript.exe' -Value 0 -Type DWord -Force
Set-ItemProperty -Path "$pol\Processes" -Name 'mshta.exe' -Value 0 -Type DWord -Force
"policy exclusions set" | Add-Content $log
# restart Defender service to apply
Restart-Service WinDefend -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
"done" | Add-Content $log
'@
$sysPath = 'C:\Windows\Temp\anxin-defender2.ps1'
Invoke-Command -Session $s -ScriptBlock { param($p,$c) [System.IO.File]::WriteAllText($p,$c,(New-Object System.Text.UTF8Encoding($false))) } -ArgumentList $sysPath, $sysScript

$r = Invoke-Command -Session $s -ScriptBlock {
    param($scriptPath)
    $out = @()
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinDisableDefender2' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinDisableDefender2'
    Start-Sleep -Seconds 12
    $ti = Get-ScheduledTaskInfo -TaskName 'AnXinDisableDefender2' -ErrorAction SilentlyContinue
    if ($ti) { $out += "task LastTaskResult=$($ti.LastTaskResult)" }
    Unregister-ScheduledTask -TaskName 'AnXinDisableDefender2' -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path 'C:\Windows\Temp\anxin-defender2.log') { $out += Get-Content 'C:\Windows\Temp\anxin-defender2.log' }
    # verify current state
    try {
        $cs = Get-MpComputerStatus
        $out += "RealTimeProtectionEnabled=$($cs.RealTimeProtectionEnabled)"
        $out += "AntivirusEnabled=$($cs.AntivirusEnabled)"
    } catch { $out += "status err: $($_.Exception.Message)" }
    ,$out
} -ArgumentList $sysPath
$r | ForEach-Object { W "  $_" }

Remove-PSSession $s
W "=== disable-defender2 done ==="
