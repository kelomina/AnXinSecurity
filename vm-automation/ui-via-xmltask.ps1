# ui-via-xmltask.ps1 - register an interactive scheduled task from an XML def
# (InteractiveToken, no password), run it so the UI starts in the test user's
# console session, then test VUL-096 (webview kill). Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-ui-xmltask.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== ui-via-xmltask @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== UI-XMLTASK @ $(Get-Date -Format HH:mm:ss) ==="
    $installDir = 'C:\Program Files\AnXinSecurity'
    $xml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Anxin UI probe</Description></RegistrationInfo>
  <Triggers />
  <Principals>
    <Principal id="Author">
      <UserId>DESKTOP-19GVBVB\test</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>C:\Program Files\AnXinSecurity\anxin-security.exe</Command></Exec>
  </Actions>
</Task>
'@
    $xmlPath = 'C:\Windows\Temp\anxin-ui-task.xml'
    [System.IO.File]::WriteAllText($xmlPath, $xml, [System.Text.Encoding]::Unicode)
    "xml written"

    schtasks.exe /delete /tn "AnxinUIProbe" /f 2>&1 | Out-Null
    $c = schtasks.exe /create /tn "AnxinUIProbe" /xml $xmlPath /f 2>&1
    "  create: $(($c|Out-String).Trim())"
    $r = schtasks.exe /run /tn "AnxinUIProbe" 2>&1
    "  run: $(($r|Out-String).Trim())"

    # wait for a webview process
    $deadline = (Get-Date).AddSeconds(90); $wv = @(); $uiPid = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $wv = @(Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue)
        $ui = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue |
              Where-Object { $_.SessionId -gt 0 -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1
        if ($ui) { $uiPid = $ui.Id }
        if ($wv.Count -gt 0) { break }
    }
    "  UI (interactive, hwnd!=0): $uiPid"
    "  webview count: $($wv.Count)"
    $wv | Select-Object -First 6 | ForEach-Object { "  wv pid=$($_.Id) session=$($_.SessionId)" }

    # ---- VUL-096: taskkill a webview process (expect DENIED) ----
    if ($wv.Count -gt 0) {
        $target = $wv | Sort-Object Id | Select-Object -First 1
        $r = & cmd.exe /c "taskkill /f /pid $($target.Id)" 2>&1
        $rc = $LASTEXITCODE
        Start-Sleep -Milliseconds 800
        $alive = [bool](Get-Process -Id $target.Id -ErrorAction SilentlyContinue)
        "  [WV-KILL] $(if ($alive) { 'DENIED' } else { 'KILLED' }) :: rc=$rc $(($r|Out-String).Trim())"
    } else { "  [WV-KILL] NO-WEBVIEW (skip)" }

    # kill the probe UI task afterwards
    schtasks.exe /end /tn "AnxinUIProbe" 2>&1 | Out-Null
    schtasks.exe /delete /tn "AnxinUIProbe" /f 2>&1 | Out-Null
    "=== UI-XMLTASK DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== ui-via-xmltask done ==="
