# diag-ui-setdiag.ps1 - properly start the UI (distinct from the --service process),
# test webview kill (VUL-096), run the standalone SET_DIAG test (VUL-099), and
# confirm protection still holds afterwards. Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-ui-setdiag.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-ui-setdiag @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

# copy the standalone SET_DIAG test to the guest
try { Copy-Item -Path 'E:\Project\HTML\AnXinSecurity\vm-automation\setdiag-test.ps1' -Destination 'C:\Windows\Temp\setdiag-test.ps1' -ToSession $s -Force; W "setdiag-test copied" }
catch { W "copy setdiag fail: $($_.Exception.Message)" }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== DIAG-UI-SETDIAG @ $(Get-Date -Format HH:mm:ss) ==="
    $installDir = 'C:\Program Files\AnXinSecurity'

    # ---- enumerate anxin-security processes and identify the UI one ----
    "--- all anxin-security processes ---"
    Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue |
      ForEach-Object { "  pid=$($_.ProcessId) cmd=$($_.CommandLine)" }
    $ui = Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue |
          Where-Object { $_.CommandLine -notmatch '--service' } | Select-Object -First 1

    # ---- start the UI if needed and wait for a webview process ----
    if (-not $ui) {
        "no UI process found, starting UI..."
        Start-Process "$installDir\anxin-security.exe" | Out-Null
        $deadline = (Get-Date).AddSeconds(90); $wv = @()
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
            $wv = @(Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue)
            if ($wv.Count -gt 0) { break }
        }
        $ui = Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue |
              Where-Object { $_.CommandLine -notmatch '--service' } | Select-Object -First 1
    } else {
        "UI already running pid=$($ui.ProcessId)"
        $wv = @(Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue)
    }
    if ($ui) { "UI pid=$($ui.ProcessId) cmd=$($ui.CommandLine)" } else { "  WARN: still no UI process" }
    "webview count: $($wv.Count)"
    $wv | Select-Object -First 5 | ForEach-Object { "  wv pid=$($_.Id)" }

    # ---- VUL-096: taskkill a webview process (expect DENIED) ----
    if ($wv.Count -gt 0) {
        $target = $wv[0]
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
    $ui2 = Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue |
           Where-Object { $_.CommandLine -notmatch '--service' } | Select-Object -First 1
    if ($ui2) {
        $r = & cmd.exe /c "taskkill /f /pid $($ui2.ProcessId)" 2>&1
        Start-Sleep -Milliseconds 800
        $alive = [bool](Get-Process -Id $ui2.ProcessId -ErrorAction SilentlyContinue)
        "  [POST-DIAG taskkill UI] $(if ($alive) { 'DENIED' } else { 'KILLED' })"
    } else { "  [POST-DIAG] no UI to test" }
    "=== DIAG-UI-SETDIAG DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== diag-ui-setdiag done ==="
