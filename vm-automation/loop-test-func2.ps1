# loop-test-func2.ps1 - 补充验证：行为库文件定位 + ProcMon 事件证据 + sc stop 完整输出。
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-loop-func2.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== loop-test-func2 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$s = $null; $deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

# 先派生一批 cmd.exe 给 ProcMon 采集，再进 guest 查库
1..5 | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c','exit' -WindowStyle Hidden }
Start-Sleep -Seconds 4

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== FUNC2 @ $(Get-Date -Format 'HH:mm:ss') ==="
    "--- A: locate behavior db ---"
    $roots = @("$env:APPDATA\AnXinSecurity", "$env:ProgramData\AnXinSecurity", "$env:LOCALAPPDATA\AnXinSecurity")
    foreach ($r in $roots) {
        if (Test-Path $r) {
            Get-ChildItem $r -Recurse -Filter '*.db' -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.FullName) $($_.Length) B" }
            Get-ChildItem "$r\audit" -ErrorAction SilentlyContinue | Select-Object -First 3 | ForEach-Object { "  audit: $($_.Name)" }
        }
    }
    "--- B: sc stop full output (driver anti-unload) ---"
    $ss = & sc.exe stop AnXinProcProtect 2>&1
    $ss | ForEach-Object { "  sc> $_" }
    Start-Sleep -Seconds 2
    $q = sc.exe query AnXinProcProtect 2>&1 | Out-String
    "  after: $((($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join '')"
    "--- C: ProcMon lifecycle db evidence (sqlite string scan) ---"
    $db = Get-ChildItem "$env:APPDATA\AnXinSecurity","$env:ProgramData\AnXinSecurity" -Recurse -Filter 'anxin_etw_behavior.db' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($db) {
        "  db found: $($db.FullName) $($db.Length) B"
        # 无 sqlite3 CLI 时用原始字节扫描 cmd.exe 痕迹（events 表 JSON payload 含进程名）
        $bytes = [IO.File]::ReadAllBytes($db.FullName)
        $text = [Text.Encoding]::ASCII.GetString($bytes)
        $hits = ([regex]::Matches($text, 'cmd\.exe')).Count
        "  raw 'cmd.exe' occurrences in db pages: $hits"
    } else { "  db NOT FOUND" }
    "=== FUNC2 DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== loop-test-func2 done ==="
