# ui-webview-setdiag.ps1 - start the real UI unconditionally, wait for a webview
# process, test VUL-096 (webview kill), then run the standalone SET_DIAG test
# (VUL-099) and confirm protection still holds. Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-ui-webview-setdiag.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== ui-webview-setdiag @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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
    "=== UI-WV-SETDIAG @ $(Get-Date -Format HH:mm:ss) ==="
    $installDir = 'C:\Program Files\AnXinSecurity'
    "--- anxin-security processes before UI start ---"
    Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue |
      ForEach-Object { "  pid=$($_.ProcessId) cmd=[$($_.CommandLine)]" }

    # ---- unconditionally start the UI (no --service) ----
    "starting UI..."
    $p = Start-Process "$installDir\anxin-security.exe" -PassThru
    "  launched UI pid=$($p.Id)"
    $deadline = (Get-Date).AddSeconds(90); $wv = @(); $uiPid = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        $wv = @(Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue)
        $ui = Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue |
              Where-Object { $_.CommandLine -and $_.CommandLine -notmatch '--service' } | Select-Object -First 1
        if ($ui) { $uiPid = $ui.ProcessId }
        if ($wv.Count -gt 0) { break }
    }
    "  UI pid (non-service): $uiPid"
    "  webview count: $($wv.Count)"
    $wv | Select-Object -First 5 | ForEach-Object { "  wv pid=$($_.Id) path=$($_.Path)" }

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
           Where-Object { $_.CommandLine -and $_.CommandLine -notmatch '--service' } | Select-Object -First 1
    if ($ui2) {
        $r = & cmd.exe /c "taskkill /f /pid $($ui2.ProcessId)" 2>&1
        Start-Sleep -Milliseconds 800
        $alive = [bool](Get-Process -Id $ui2.ProcessId -ErrorAction SilentlyContinue)
        "  [POST-DIAG taskkill UI] $(if ($alive) { 'DENIED' } else { 'KILLED' })"
    } else { "  [POST-DIAG] no UI to test" }
    "=== UI-WV-SETDIAG DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== ui-webview-setdiag done ==="
