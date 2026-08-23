# loop-test-func4.ps1 - 排查行为库未写入：应用日志、服务日志、ProcMon 客户端连接痕迹。
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-loop-func4.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== loop-test-func4 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$s = $null; $deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== FUNC4 @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
    "--- guest now / db mtime ---"
    "now: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $db = "$env:APPDATA\AnXinSecurity\data\behavior\anxin_etw_behavior.db"
    if (Test-Path $db) { "db mtime: $((Get-Item $db).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) size $((Get-Item $db).Length)" }
    "--- APPDATA AnXinSecurity tree (top 2 levels) ---"
    Get-ChildItem "$env:APPDATA\AnXinSecurity" -Depth 1 -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Replace($env:APPDATA, '~')
        if ($_.PSIsContainer) { "  $rel <dir>" } else { $mt = $_.LastWriteTime.ToString('MM-dd HH:mm'); "  $rel $($_.Length)B mtime=$mt" }
    }
    "--- runtime dir (interception/blackbox logs) ---"
    Get-ChildItem "$env:APPDATA\AnXinSecurity\runtime" -ErrorAction SilentlyContinue | ForEach-Object { "  rt: $($_.Name) $($_.Length)B $($_.LastWriteTime.ToString('MM-dd HH:mm'))" }
    "--- anxin processes detail ---"
    Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
        "  pid=$($_.ProcessId) parent=$($_.ParentProcessId) session=$($_.SessionId) start=$($_.CreationDate.ToString('MM-dd HH:mm:ss'))"
        "    cmdline: $($_.CommandLine)"
    }
    "--- System log: AnXin service events last 20min ---"
    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-25)} -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'AnXin' -or $_.ProviderName -match 'AnXin' } |
      Select-Object -First 10 | ForEach-Object { "  [$($_.TimeCreated.ToString('HH:mm:ss'))] $($_.ProviderName) id=$($_.Id): $($_.Message.Split("`n")[0])" }
    "=== FUNC4 DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== loop-test-func4 done ==="
