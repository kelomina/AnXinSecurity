# rerun-uninstall-drivers.ps1 - run --uninstall-drivers again on the guest and
# capture its per-step report to see exactly which step blocks. Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-rerun-uninstall.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== rerun-uninstall-drivers @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== RERUN-UNINSTALL @ $(Get-Date -Format HH:mm:ss) ==="
    $exe = 'C:\Program Files\AnXinSecurity\anxin-security.exe'
    "--- services before ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        "  $svc : $(if ($q -match 'does not exist|1060') { 'gone' } else { ((($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join '') })"
    }
    "--- run --uninstall-drivers (capture all output) ---"
    $r = & cmd.exe /c "`"$exe`" --uninstall-drivers 2>&1" 2>&1
    "  rc=$LASTEXITCODE"
    $r | ForEach-Object { "  OUT: $_" }
    "--- services after ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        "  $svc : $(if ($q -match 'does not exist|1060') { 'gone' } else { ((($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join '') })"
    }
    "--- driver files after ---"
    Get-ChildItem 'C:\Windows\System32\drivers\AnXin*' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.Name) $($_.Length) B" }
    "--- PFRO after ---"
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $pfro | ForEach-Object { "  PFRO: $_" } } else { "  no PFRO" }
    "=== RERUN-UNINSTALL DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== rerun-uninstall-drivers done ==="
