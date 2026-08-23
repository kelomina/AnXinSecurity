# read-fpdiag.ps1 - read the guest's C:\Windows\Temp\anxin-fp-diag.log
# to locate where --protect-dir / --service crashes (connect vs send phase).
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-read-fpdiag.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== read-fpdiag @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== READ-FPDIAG @ $(Get-Date -Format HH:mm:ss) ==="
    $f = 'C:\Windows\Temp\anxin-fp-diag.log'
    if (Test-Path $f) {
        "--- raw content ---"
        Get-Content $f -ErrorAction SilentlyContinue | ForEach-Object { "  $_" }
        "--- tail 30 ---"
        Get-Content $f -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object { "  T: $_" }
        "--- size ---"
        "  size=$((Get-Item $f).Length) modified=$((Get-Item $f).LastWriteTime.ToString('MM-dd HH:mm:ss'))"
    } else { "  NO diag log file" }
    "=== READ-FPDIAG DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== read-fpdiag done ==="
