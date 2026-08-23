# check-netfilter.ps1 - resolve why sc query AnXinNetFilter reports NOT-REGISTERED
# despite the registry key existing. Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-netfilter.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== check-netfilter @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== CHECK-NETFILTER @ $(Get-Date -Format HH:mm:ss) ==="
    "--- sc query raw (stdout+stderr, byte-exact) ---"
    & cmd.exe /c "sc query AnXinNetFilter 2>&1" 2>&1 | ForEach-Object { "  RAW: $_" }
    "  LASTEXITCODE=$LASTEXITCODE"
    "--- sc qc raw ---"
    & cmd.exe /c "sc qc AnXinNetFilter 2>&1" 2>&1 | ForEach-Object { "  QC: $_" }
    "--- service key all values ---"
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\AnXinNetFilter'
    if (Test-Path $k) {
        $p = Get-ItemProperty $k
        $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "  $($_.Name) = $($_.Value)" }
        "  subkeys: $((@(Get-ChildItem $k -ErrorAction SilentlyContinue)).Count)"
        Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object { "    subkey: $($_.PSChildName)" }
    } else { "  NO KEY" }
    "--- other AnXin services for comparison ---"
    & cmd.exe /c "sc qc AnXinFileProtect 2>&1" 2>&1 | Select-Object -First 8 | ForEach-Object { "  FPLogic: $_" }
    "=== CHECK-NETFILTER DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== check-netfilter done ==="
