# probe-postinstall.ps1 - after installer ran, check NetFilter service state,
# try to start the user-mode service, and check whether file-protection paths
# got registered (--query-file-protect). Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-postinstall-probe.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== probe-postinstall @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== POSTINSTALL-PROBE @ $(Get-Date -Format HH:mm:ss) ==="
    "--- all AnXin service keys ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        if (Test-Path $k) { $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; "  $svc Start=$($p.Start) Type=$($p.Type) ImagePath=$($p.ImagePath)" }
        else { "  $svc NO KEY" }
    }
    "--- try start AnXinSecurityService ---"
    $r = sc.exe start AnXinSecurityService 2>&1 | Out-String
    Start-Sleep -Seconds 6
    $q = sc.exe query AnXinSecurityService 2>&1 | Out-String
    "  start: $($r.Trim())"
    "  query: $((($q -split "`r?`n") | Where-Object { $_ -match 'STATE|SERVICE_NAME|EXIT_CODE' }) -join ' | ')"
    "--- try sc create NetFilter to surface the error ---"
    $n = sc.exe create "AnXinNetFilter" type= kernel start= system error= normal binPath= "C:\Windows\System32\drivers\AnXinNetFilter.sys" DisplayName= "AnXin Security Network Filter" depend= "Tcpip" 2>&1 | Out-String
    "  net create: $($n.Trim())"
    $q2 = sc.exe query AnXinNetFilter 2>&1 | Out-String
    "  net query: $((($q2 -split "`r?`n") | Where-Object { $_ -match 'STATE|SERVICE_NAME' }) -join ' | ')"
    "--- query-file-protect ---"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $q3 = & 'C:\Program Files\AnXinSecurity\anxin-security.exe' --query-file-protect 2>&1
    $sw.Stop()
    "  query-file-protect ($([math]::Round($sw.Elapsed.TotalSeconds,2))s): $(($q3 | Out-String).Trim())"
    "=== POSTINSTALL-PROBE DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== probe-postinstall done ==="
