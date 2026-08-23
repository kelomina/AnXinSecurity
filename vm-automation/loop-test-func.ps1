# loop-test-func.ps1 - 2026-08-17 闭环测试功能验证：ProcMon 驱动/事件、
# 进程自保（taskkill）、minifilter 注册、行为数据库。Host-side, PS Direct.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-loop-func.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== loop-test-func @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== FUNC-TEST @ $(Get-Date -Format 'HH:mm:ss') ==="

    # --- T1: ProcMon 驱动服务状态（DEMAND_START，应由 ProcessLifecycleService sc start）---
    "--- T1 ProcMon service ---"
    $q = sc.exe query AnXinProcMon 2>&1 | Out-String
    if ($q -match '1060|does not exist') { "  AnXinProcMon: NOT-REGISTERED" }
    else {
        $st = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        "  AnXinProcMon: $st"
    }

    # --- T2: minifilter 注册（fltmc：FileProtect 328800 + ProcMon 380000）---
    "--- T2 fltmc filters ---"
    $flt = fltmc filters 2>&1 | Out-String
    ($flt -split "`r?`n") | Where-Object { $_ -match 'AnXin' } | ForEach-Object { "  $_" }

    # --- T3: ProcMon 设备连接 + 健康检查（--query-procmon-health 若有；否则探针）---
    "--- T3 ProcMon probe (spawn cmd.exe x3, check event pump) ---"
    1..3 | ForEach-Object { Start-Process cmd.exe -ArgumentList '/c','exit' -WindowStyle Hidden -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 3

    # --- T4: 进程自保 - taskkill anxin-security（期望 DENIED）---
    "--- T4 taskkill self-protect (expect DENIED) ---"
    $tk = taskkill /f /im anxin-security.exe 2>&1 | Out-String
    "  taskkill: $($tk.Trim() -replace "`r?`n", ' | ')"

    # --- T5: 服务自保 - sc stop AnXinProcProtect（期望 STOP_PENDING 挂起）---
    "--- T5 sc stop driver (expect STOP_PENDING/blocked) ---"
    $ss = sc.exe stop AnXinProcProtect 2>&1 | Out-String
    "  sc stop: $(($ss -split "`r?`n" | Where-Object { $_ -match 'STATE|FAILED|1051|1062' }) -join ' ')"

    # --- T6: 注册表键保护 - reg delete 驱动服务键（期望 DENIED）---
    "--- T6 reg delete service key (expect DENIED) ---"
    $rd = reg delete HKLM\SYSTEM\CurrentControlSet\Services\AnXinProcProtect /f 2>&1 | Out-String
    "  reg delete: $($rd.Trim())"

    # --- T7: 行为数据库（ProcMon 事件入库证据）---
    "--- T7 behavior db ---"
    $db = "$env:ProgramData\AnXinSecurity\behavior.db"
    $db2 = "$env:APPDATA\AnXinSecurity\behavior.db"
    foreach ($d in @($db, $db2)) { if (Test-Path $d) { "  db: $d $((Get-Item $d).Length) B" } }

    # --- T8: UI 进程仍在（T4 taskkill 后应存活）---
    "--- T8 UI alive after taskkill ---"
    Get-Process -Name 'anxin-security*' -ErrorAction SilentlyContinue | ForEach-Object { "  pid=$($_.Id)" }

    # --- T9: System 日志蓝屏/驱动错误---
    "--- T9 system log errors ---"
    $ev = Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1001,219; StartTime=(Get-Date).AddMinutes(-30)} -ErrorAction SilentlyContinue
    if ($ev) { $ev | Select-Object -First 5 | ForEach-Object { "  [ERR] id=$($_.Id) $($_.Message.Split("`n")[0])" } } else { "  clean (no 41/1001/219 in last 30min)" }

    "=== FUNC-TEST DONE @ $(Get-Date -Format 'HH:mm:ss') ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== loop-test-func done ==="
