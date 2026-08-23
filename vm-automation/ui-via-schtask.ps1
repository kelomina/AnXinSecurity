# ui-via-schtask.ps1 - launch the UI in the test user's interactive session via a
# scheduled interactive task (PS Direct runs in session 0, where WebView2 cannot
# initialize), then test VUL-096 (webview kill) and VUL-099 (SET_DIAG). Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-ui-schtask.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== ui-via-schtask @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

try { Copy-Item -Path 'E:\Project\HTML\AnXinSecurity\vm-automation\setdiag-test.ps1' -Destination 'C:\Windows\Temp\setdiag-test.ps1' -ToSession $s -Force; W "setdiag-test copied" }
catch { W "copy setdiag fail: $($_.Exception.Message)" }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== UI-SCHTASK @ $(Get-Date -Format HH:mm:ss) ==="
    $installDir = 'C:\Program Files\AnXinSecurity'

    # which sessions have an interactive explorer?
    "--- explorer sessions ---"
    Get-Process -Name 'explorer' -ErrorAction SilentlyContinue | ForEach-Object { "  explorer pid=$($_.Id) session=$($_.SessionId)" }

    # remove any stale task, then create an interactive task that runs the UI
    schtasks.exe /delete /tn "AnxinUIProbe" /f 2>&1 | Out-Null
    $tr = "`"$installDir\anxin-security.exe`""
    $c = schtasks.exe /create /tn "AnxinUIProbe" /tr $tr /sc once /st 00:00 /it /ru "$env:COMPUTERNAME\test" /rp 'Kolomina520!' /f 2>&1
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
    $wv | Select-Object -First 5 | ForEach-Object { "  wv pid=$($_.Id) session=$($_.SessionId) path=$($_.Path)" }

    # ---- VUL-096: taskkill a webview process (expect DENIED) ----
    if ($wv.Count -gt 0) {
        $target = $wv | Sort-Object Id | Select-Object -First 1
        $r = & cmd.exe /c "taskkill /f /pid $($target.Id)" 2>&1
        $rc = $LASTEXITCODE
        Start-Sleep -Milliseconds 800
        $alive = [bool](Get-Process -Id $target.Id -ErrorAction SilentlyContinue)
        "  [WV-KILL] $(if ($alive) { 'DENIED' } else { 'KILLED' }) :: rc=$rc $(($r|Out-String).Trim())"
    } else { "  [WV-KILL] NO-WEBVIEW (skip)" }

    # ---- VUL-099: standalone SET_DIAG test (expect REFUSED) ----
    "--- SET_DIAG standalone (expect REFUSED) ---"
    $sd = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Windows\Temp\setdiag-test.ps1' 2>&1
    $sd | ForEach-Object { "  DIAG: $_" }

    # ---- confirm protection still holds after SET_DIAG ----
    $ui2 = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue |
           Where-Object { $_.SessionId -gt 0 -and $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if ($ui2) {
        $r = & cmd.exe /c "taskkill /f /pid $($ui2.Id)" 2>&1
        Start-Sleep -Milliseconds 800
        $alive = [bool](Get-Process -Id $ui2.Id -ErrorAction SilentlyContinue)
        "  [POST-DIAG taskkill UI] $(if ($alive) { 'DENIED' } else { 'KILLED' })"
    } else { "  [POST-DIAG] no interactive UI to test" }

    schtasks.exe /delete /tn "AnxinUIProbe" /f 2>&1 | Out-Null
    "=== UI-SCHTASK DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== ui-via-schtask done ==="
