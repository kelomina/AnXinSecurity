# diag-ui.ps1 - diagnose why the UI process (anxin-security.exe without --service)
# starts but no webview appears / process vanishes. Check process liveness, window
# handle, and Application crash logs. Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-ui.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-ui @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== DIAG-UI @ $(Get-Date -Format HH:mm:ss) ==="
    $installDir = 'C:\Program Files\AnXinSecurity'
    "--- all anxin-security processes right now ---"
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue |
      ForEach-Object { "  $($_.Name) pid=$($_.Id) hwnd=$($_.MainWindowHandle) title=[$($_.MainWindowTitle)] resp=$($_.Responding) start=$($_.StartTime.ToString('HH:mm:ss'))" }

    "--- launch UI and watch its lifecycle ---"
    $p = Start-Process "$installDir\anxin-security.exe" -PassThru
    "  launched pid=$($p.Id)"
    foreach ($t in 2,5,10,20) {
        Start-Sleep -Seconds $t
        $alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
        if ($alive) {
            "  +${t}s: alive hwnd=$($alive.MainWindowHandle) title=[$($alive.MainWindowTitle)] webview=$(@(Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue).Count)"
        } else {
            "  +${t}s: DEAD (exited)"
            break
        }
    }

    "--- Application event log last 10 min (anxin / errors) ---"
    $since = (Get-Date).AddMinutes(-10)
    Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$since } -ErrorAction SilentlyContinue |
      Where-Object { $_.ProviderName -match 'Application Error|Windows Error Reporting|\.NET Runtime' -or $_.Message -match 'anxin' } |
      Select-Object -First 8 TimeCreated, Id, ProviderName, @{n='m';e={($_.Message -split "`r?`n")[0..8] -join ' | '}} |
      ForEach-Object { "[$($_.TimeCreated.ToString('HH:mm:ss'))] id=$($_.Id) prov=$($_.ProviderName)`n    $($_.m)" }

    "--- is there a window station / session 0 issue? current session ---"
    "  sessionid=$((Get-Process -Id $PID).SessionId) user=$(whoami)"
    "  explorer sessions: $(@(Get-Process -Name 'explorer' -ErrorAction SilentlyContinue).Count)"
    "=== DIAG-UI DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== diag-ui done ==="
