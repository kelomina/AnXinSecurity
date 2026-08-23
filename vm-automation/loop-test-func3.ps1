# loop-test-func3.ps1 - ProcMon 入库间接证据：db mtime/WAL 活跃度 + audit 日志。
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-loop-func3.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== loop-test-func3 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$s = $null; $deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }

# 第一采样
$out1 = Invoke-Command -Session $s -ScriptBlock {
    $d = "$env:APPDATA\AnXinSecurity\data\behavior"
    Get-ChildItem $d -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Length)|$($_.LastWriteTime.ToString('HH:mm:ss'))" }
}
Start-Sleep -Seconds 20
# 派生进程 + 第二采样
1..5 | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c','exit' -WindowStyle Hidden }
Start-Sleep -Seconds 6
$out2 = Invoke-Command -Session $s -ScriptBlock {
    $d = "$env:APPDATA\AnXinSecurity\data\behavior"
    "--- sample2 ---"
    Get-ChildItem $d -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)|$($_.Length)|$($_.LastWriteTime.ToString('HH:mm:ss'))" }
    "--- audit dir ---"
    Get-ChildItem "$env:APPDATA\AnXinSecurity\audit" -ErrorAction SilentlyContinue | ForEach-Object { "audit: $($_.Name) $($_.Length) B" }
    "--- audit tail (last 3 lines of today) ---"
    $f = Get-ChildItem "$env:APPDATA\AnXinSecurity\audit" -Filter '*.jsonl' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($f) { Get-Content $f.FullName -Tail 3 | ForEach-Object { "  $_" } }
}
W "--- sample1 ---"
$out1 | ForEach-Object { W $_ }
$out2 | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== loop-test-func3 done ==="
