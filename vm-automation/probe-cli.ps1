# probe-cli.ps1 - deep-diagnose the empty --query-file-protect output and the
# AnXinSecurityService 1067 crash. Runs CLI with full output capture + checks
# Application event log for the crash. Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-probe-cli.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== probe-cli @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== CLI-PROBE @ $(Get-Date -Format HH:mm:ss) ==="
    $exe = 'C:\Program Files\AnXinSecurity\anxin-security.exe'
    "--- --query-file-protect via cmd (stdout+stderr to file) ---"
    & cmd.exe /c "`"$exe`" --query-file-protect > C:\Windows\Temp\qfp-out.txt 2> C:\Windows\Temp\qfp-err.txt & echo EXITCODE=%ERRORLEVEL%"
    "  exitcode line above"
    "  stdout: [$(Get-Content C:\Windows\Temp\qfp-out.txt -Raw -ErrorAction SilentlyContinue)]"
    "  stderr: [$(Get-Content C:\Windows\Temp\qfp-err.txt -Raw -ErrorAction SilentlyContinue)]"
    "--- --query-file-protect via cmd direct ---"
    $cmdR = & cmd.exe /c "`"$exe`" --query-file-protect 2>&1" 2>&1
    "  rc=$LASTEXITCODE"
    $cmdR | ForEach-Object { "  OUT: $_" }

    "--- --protect-dir retry (authorized CLI, expect Directory now protected) ---"
    $pr = & cmd.exe /c "`"$exe`" --protect-dir `"C:\Program Files\AnXinSecurity`" 2>&1" 2>&1
    "  rc=$LASTEXITCODE"
    $pr | ForEach-Object { "  PDIR: $_" }
    Start-Sleep -Seconds 2
    $q2 = & cmd.exe /c "`"$exe`" --query-file-protect 2>&1" 2>&1
    $q2 | ForEach-Object { "  QFP2: $_" }

    "--- AnXinSecurityService crash events (last 30 min) ---"
    $since = (Get-Date).AddMinutes(-30)
    Get-WinEvent -FilterHashtable @{ LogName='Application'; StartTime=$since } -ErrorAction SilentlyContinue |
      Where-Object { $_.Id -in 1000,1001,1026,1067 -or $_.ProviderName -match 'Application Error|\.NET Runtime|Windows Error Reporting' } |
      Select-Object -First 6 TimeCreated, Id, ProviderName, @{n='m';e={($_.Message -split "`r?`n")[0..6] -join ' | '}} |
      ForEach-Object { "[$($_.TimeCreated.ToString('HH:mm:ss'))] id=$($_.Id) prov=$($_.ProviderName)`n    $($_.m)" }

    "--- try starting service, capture service log output if any ---"
    sc.exe start AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 8
    $q = sc.exe query AnXinSecurityService 2>&1 | Out-String
    "  service: $((($q -split "`r?`n") | Where-Object { $_ -match 'STATE|WIN32_EXIT' }) -join ' | ')"
    "=== CLI-PROBE DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== probe-cli done ==="
