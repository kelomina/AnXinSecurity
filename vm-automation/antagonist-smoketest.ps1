# antagonist-smoketest.ps1 - confirm Defender exclusion unblocks sample launch.
# Reads the sample path from the manifest CSV (avoids hardcoding CJK in source).
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-defender-smoke.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== defender smoke v2 @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

$csv = 'E:\Project\HTML\AnXinSecurity\vm-automation\output\sample-batch-20260818.csv'
$row = Import-Csv -Encoding UTF8 -Path $csv | Where-Object { $_.Seq -eq '1' }
$sample = $row.OriginalPath
W "sample path from CSV: $sample"

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

Invoke-Command -Session $s -ScriptBlock { if (Test-Path 'C:\Samples\smoke') { Remove-Item 'C:\Samples\smoke' -Recurse -Force -ErrorAction SilentlyContinue }; New-Item -ItemType Directory -Path 'C:\Samples\smoke' -Force | Out-Null; 'smoke dir ready' } | ForEach-Object { W $_ }

Copy-Item -LiteralPath $sample -Destination 'C:\Samples\smoke\sample1.exe' -ToSession $s -Force
W "copied sample1.exe to VM"

$out = Invoke-Command -Session $s -ScriptBlock {
    "--- start sample1.exe ---"
    try {
        $p = Start-Process -FilePath 'C:\Samples\smoke\sample1.exe' -PassThru -ErrorAction Stop
        "started pid=$($p.Id)"
        Start-Sleep -Seconds 3
        $alive = Get-Process -Id $p.Id -ErrorAction SilentlyContinue
        if ($alive) { "ALIVE after 3s (launch NOT blocked by Defender)" } else { "EXITED within 3s" }
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        "killed"
    } catch {
        "START ERR: $($_.Exception.Message)"
    }
    "--- exclusion still set ---"
    (Get-MpPreference).ExclusionPath -join ';'
    "--- cleanup smoke dir ---"
    if (Test-Path 'C:\Samples\smoke') { Remove-Item 'C:\Samples\smoke' -Recurse -Force -ErrorAction SilentlyContinue; 'removed' }
}
$out | ForEach-Object { W $_; Write-Output $_ }
Remove-PSSession $s
"=== smoke done ===" | Add-Content $LogPath
