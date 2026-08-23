# loop-test-func6.ps1 - 最终强化：派生进程前后行为库增长对比（ProcMon→SQLite 入库闭环证据）。
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-loop-func6.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== loop-test-func6 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$s = $null; $deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }

$db = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\data\behavior\anxin_etw_behavior.db'
$size1 = Invoke-Command -Session $s -ScriptBlock { param($p) if (Test-Path $p) { (Get-Item $p).Length } else { -1 } } -ArgumentList $db
W "sample1: $size1 B"

1..15 | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c','exit' -WindowStyle Hidden }
Start-Sleep -Seconds 8

$size2 = Invoke-Command -Session $s -ScriptBlock { param($p) (Get-Item $p).Length } -ArgumentList $db
W "sample2: $size2 B (after 15x cmd.exe spawn + 8s)"
W "delta: $($size2 - $size1) B"
Remove-PSSession $s
W "=== loop-test-func6 done ==="
