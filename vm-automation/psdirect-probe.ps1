# Elevated: start VM, aggressively poll PS Direct (every 2s, ~170s window),
# on connect gather shutdown-source diagnostics + try to neutralize WMI consumers.
$ErrorActionPreference = 'Continue'
$vmId = '7b66415c-52cb-468e-b9bd-368746f42863'
$log = 'C:\Users\Saika\AppData\Local\Temp\anxin-psdirect.log'
function W([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
"=== psdirect @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

$vm = Get-VM -Id $vmId
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started @ $(Get-Date -Format HH:mm:ss)" } else { W "VM already running" }

$user = 'test'; $pass = 'Kolomina520!'
$sec = ConvertTo-SecureString $pass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", $sec)

$deadline = (Get-Date).AddSeconds(170)
$connected = $false
$firstErr = $null
while ((Get-Date) -lt $deadline) {
    try {
        $s = New-PSSession -VMId $vmId -Credential $cred -ErrorAction Stop
        $connected = $true
        W "CONNECTED @ $(Get-Date -Format HH:mm:ss)"
        try {
            $diag = Invoke-Command -Session $s -ScriptBlock {
                "GUEST-DATE: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                "UPTIME-MIN: " + [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalMinutes, 2)
                "WHOAMI: " + (whoami)
                "--- 1074 shutdown events ---"
                Get-WinEvent -LogName System -MaxEvents 400 -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq 1074 } | Select-Object -First 6 TimeCreated, @{n='m'; e={$_.Message}} | ForEach-Object { "[$($_.TimeCreated.ToString('MM-dd HH:mm:ss'))] " + (($_.m -split "`r?`n")[0]) }
                "--- WMI __EventConsumer ---"
                Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object { "CONSUMER: $($_.Name) :: $(([string]($_ | ConvertTo-Json -Compress)).Substring(0,[Math]::Min(300,([string]($_ | ConvertTo-Json -Compress)).Length)))" }
                "--- WMI __EventFilter ---"
                Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object { "FILTER: $($_.Name) :: $($_.Query -replace "`r?`n", ' ')" }
                "--- WMI __FilterToConsumerBinding ---"
                Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object { "BINDING: $($_.Consumer) -> $($_.Filter)" }
                "--- tasks w/ shutdown/restart ---"
                Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { (($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ') -match 'shutdown|restart|Stop-Computer|ExitWindows|wpeutil' } | ForEach-Object { "TASK: $($_.TaskPath)$($_.TaskName) [state=$($_.State)]" }
                "--- non-MS services (anxin/360/test/watchdog) ---"
                Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'anxin|360|watchdog|anxin-security' } | ForEach-Object { "SVC: $($_.Name) = $($_.State) start=$($_.StartMode) :: $($_.PathName)" }
                "--- HKLM Run / RunOnce ---"
                (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue) | Out-String
                (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue) | Out-String
                "--- process tree (non-MS top) ---"
                Get-Process -ErrorAction SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 15 Name,Id,CPU,Path | ForEach-Object { "PROC: $($_.Name) pid=$($_.Id) cpu=$($_.CPU)" }
            }
            $diag | Add-Content $log
        } catch { W "diag err: $($_.Exception.Message)" }
        # neutralize WMI consumers that target shutdown
        try {
            Invoke-Command -Session $s -ScriptBlock {
                $bad = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'shutdown|power|off|stop' -or $_.CommandLineTemplate -match 'shutdown' -or $_.ScriptText -match 'shutdown' }
                foreach ($b in $bad) { Remove-CimInstance -InputObject $b -ErrorAction SilentlyContinue; "REMOVED-CONSUMER: $($b.Name)" }
                "neutralize-ok"
            } | Add-Content $log
        } catch { W "neutralize err: $($_.Exception.Message)" }
        break
    } catch {
        if (-not $firstErr) { $firstErr = $_.Exception.Message; W "first err: $firstErr" }
    }
    Start-Sleep -Seconds 2
}
W "done connected=$connected @ $(Get-Date -Format HH:mm:ss)"
if ($connected) { try { Remove-PSSession -Session $s -ErrorAction SilentlyContinue } catch {} }
W "=== psdirect done ==="
