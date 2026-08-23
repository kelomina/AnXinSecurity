# verify-install.ps1 - post-install verification: service states, query-file-protect
# (expect 2 paths now that register send no longer crashes), NetFilter service key,
# and the fp_diag log tail. Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-verify-install.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== verify-install @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== VERIFY-INSTALL @ $(Get-Date -Format HH:mm:ss) ==="
    "--- services ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        $reg = if ($q -match 'does not exist|1060') { 'NOT-REGISTERED' } else { 'registered' }
        "  $svc : $reg $state"
    }
    "--- NetFilter registry key ---"
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\AnXinNetFilter'
    if (Test-Path $k) { $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; "  KEY: Start=$($p.Start) Type=$($p.Type) ImagePath=$($p.ImagePath)" } else { "  NO KEY" }
    "--- --query-file-protect (expect quick + >=1 path) ---"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $q3 = & cmd.exe /c "`"C:\Program Files\AnXinSecurity\anxin-security.exe`" --query-file-protect 2>&1" 2>&1
    $sw.Stop()
    "  elapsed=$([math]::Round($sw.Elapsed.TotalSeconds,2))s rc=$LASTEXITCODE"
    $q3 | ForEach-Object { "  Q: $_" }
    "--- fp_diag log tail ---"
    if (Test-Path 'C:\Windows\Temp\anxin-fp-diag.log') { Get-Content 'C:\Windows\Temp\anxin-fp-diag.log' -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { "  D: $_" } } else { "  no diag log" }
    "--- running anxin processes ---"
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) pid=$($_.Id)" }
    "=== VERIFY-INSTALL DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== verify-install done ==="
