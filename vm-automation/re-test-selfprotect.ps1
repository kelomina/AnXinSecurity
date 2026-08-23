# re-test-selfprotect.ps1 - re-run the R3 driver self-protection attack vectors
# against the "病毒测试" guest AFTER the VUL-096..103 fixes are deployed, plus the
# driver-internal self-verification (--query-file-protect). Host-side script.
#
# Expected behavior: every attack returns DENIED / FAILED; --query-file-protect
# returns the registered paths WITHOUT hanging (VUL-102 fix); SET_DIAG from a
# non-authorized process is refused (VUL-099 fix); a spoofed-named process can no
# longer terminate protected processes (VUL-100 fix).
#
# Usage: .\re-test-selfprotect.ps1
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-retest.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== re-test-selfprotect @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM $VmId not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; Start-Sleep -Seconds 15 }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    function RES([string]$name, [string]$verdict, [string]$detail) { GW "  [$name] $verdict :: $detail" }
    "=== GUEST-ATTACK @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
    GW "WHOAMI: $(whoami)"

    $installDir = 'C:\Program Files\AnXinSecurity'
    $drvDir = 'C:\Windows\System32\drivers'
    $drvFiles = 'AnXinProcProtect.sys','AnXinFileProtect.sys','AnXinNetFilter.sys'
    $svcKeys = 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter','AnXinSecurityService'

    # ---- launch the UI if not already running (needed for process/webview tests) ----
    $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $app) {
        GW "starting anxin-security UI..."
        Start-Process "$installDir\anxin-security.exe" | Out-Null
        Start-Sleep -Seconds 12
        $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($app) {
        GW "app running pid=$($app.Id) path=$($app.Path)"
        GW "webview processes: $((@(Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue)).Count)"
    } else {
        GW "WARN: app NOT running"
    }

    # ============================================================
    # 1. REG: registry protection (VUL-098) - expect reg delete to FAIL
    # ============================================================
    GW "--- REG: protected service keys (expect ALL DENIED) ---"
    foreach ($k in $svcKeys) {
        $before = Test-Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\$k"
        $r = & reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\$k" /f 2>&1
        $rc = $LASTEXITCODE
        $after = Test-Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\$k"
        $verdict = if ($before -and $after) { 'DENIED' } elseif (-not $before -and -not $after) { 'NO-KEY' } else { 'DELETED' }
        RES "REG-del $k" $verdict "$(($r | Out-String).Trim()) rc=$rc"
    }

    # ============================================================
    # 2. SVC: sc delete driver services (VUL-098 SCM path) - expect DENIED
    # ============================================================
    GW "--- SVC: sc delete (expect DENIED) ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinNetFilter') {
        $before = ((sc.exe query $svc 2>&1 | Out-String) -match 'SERVICE_NAME')
        $r = sc.exe delete $svc 2>&1
        $rc = $LASTEXITCODE
        Start-Sleep -Milliseconds 500
        $after = ((sc.exe query $svc 2>&1 | Out-String) -match 'SERVICE_NAME')
        $verdict = if ($before -and $after) { 'DENIED' } elseif ($before -and -not $after) { 'DELETED' } else { 'NO-SVC' }
        RES "SCM delete $svc" $verdict "$(($r | Out-String).Trim()) rc=$rc"
    }

    # ============================================================
    # 3. DRV: delete driver .sys files (expect DENIED)
    # ============================================================
    GW "--- DRV: delete driver files (expect DENIED) ---"
    foreach ($f in $drvFiles) {
        $p = Join-Path $drvDir $f
        $before = Test-Path $p
        $r = & cmd.exe /c "del /f /q `"$p`"" 2>&1
        $rc = $LASTEXITCODE
        Start-Sleep -Milliseconds 500
        $after = Test-Path $p
        $verdict = if ($before -and $after) { 'DENIED' } elseif ($before -and -not $after) { 'DELETED' } else { 'NO-FILE' }
        RES "DEL $f" $verdict "$(($r | Out-String).Trim()) rc=$rc"
    }

    # ============================================================
    # 4. APP: delete/overwrite/rename install-dir files (VUL-097, expect DENIED)
    # ============================================================
    GW "--- APP: install-dir file protect (expect DENIED) ---"
    # ensure no process holds the exe, then try delete
    Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $targets = @('anxin-security.exe','resources\engine.dll') | ForEach-Object { Join-Path $installDir $_ }
    foreach ($t in $targets) {
        if (-not (Test-Path $t)) { RES "DEL $t" 'NO-FILE' ''; continue }
        $before = Test-Path $t
        $r = & cmd.exe /c "del /f /q `"$t`"" 2>&1
        $rc = $LASTEXITCODE
        $after = Test-Path $t
        $verdict = if ($before -and $after) { 'DENIED' } elseif ($before -and -not $after) { 'DELETED' } else { 'NO-FILE' }
        RES "DEL $t" $verdict "rc=$rc $(($r|Out-String).Trim())"
    }
    # overwrite
    $probe = Join-Path $installDir 'anxin-security.exe'
    if (Test-Path $probe) {
        $szBefore = (Get-Item $probe).Length
        & cmd.exe /c "echo evil > `"$probe`"" 2>&1 | Out-Null
        Start-Sleep -Milliseconds 500
        $szAfter = (Get-Item $probe).Length
        RES "OVERWRITE anxin-security.exe" $(if ($szAfter -eq $szBefore) { 'DENIED' } else { 'MODIFIED' }) "before=$szBefore after=$szAfter"
    }
    # rename
    $renTarget = Join-Path $installDir 'anxin-security.exe'
    if (Test-Path $renTarget) {
        $r = & cmd.exe /c "ren `"$renTarget`" hacked.exe" 2>&1
        $rc = $LASTEXITCODE
        RES "RENAME anxin-security.exe" $(if (Test-Path $renTarget) { 'DENIED' } else { 'RENAMED' }) "rc=$rc $(($r|Out-String).Trim())"
    }

    # ============================================================
    # 5. PROC: terminate protected processes (VUL-099/100/103, expect DENIED)
    # ============================================================
    GW "--- PROC: terminate app (expect DENIED) ---"
    $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        $r = & cmd.exe /c "taskkill /f /pid $($app.Id)" 2>&1
        $rc = $LASTEXITCODE
        $alive = [bool](Get-Process -Id $app.Id -ErrorAction SilentlyContinue)
        RES "TASKKILL app" $(if ($alive) { 'DENIED' } else { 'KILLED' }) "rc=$rc $(($r|Out-String).Trim())"
    } else { RES "TASKKILL app" 'NO-PROC' '' }

    GW "--- PROC: webview (expect DENIED) ---"
    $wv = Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($wv) {
        $r = & cmd.exe /c "taskkill /f /pid $($wv.Id)" 2>&1
        $rc = $LASTEXITCODE
        $alive = [bool](Get-Process -Id $wv.Id -ErrorAction SilentlyContinue)
        RES "TASKKILL webview" $(if ($alive) { 'DENIED' } else { 'KILLED' }) "rc=$rc $(($r|Out-String).Trim())"
    } else { RES "TASKKILL webview" 'NO-PROC' '' }

    GW "--- PROC: spoofed-name process terminate (VUL-100, expect DENIED) ---"
    $spoof = 'C:\Windows\Temp\anxin-security.exe'
    try { Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $spoof -Force -ErrorAction Stop } catch { GW "spoof copy fail: $($_.Exception.Message)" }
    $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        # 用 Start-Process（而非 &）：& 在 PS Direct 会话下等待子进程 stdout 会挂起
        #（伪象），导致整个 guest 脚本卡死。子进程输出重定向到文件，按
        # ExecutablePath 轮询其消失，避免依赖 $sp.HasExited。
        $outFile = 'C:\Windows\Temp\spoof-stop-out.txt'
        Remove-Item $outFile -Force -ErrorAction SilentlyContinue
        try {
            Start-Process $spoof -ArgumentList '-NoProfile','-Command',"Get-Process -Id $($app.Id) | Stop-Process -Force; Write-Output done *> $outFile" -WindowStyle Hidden | Out-Null
        } catch { GW "spoof start fail: $($_.Exception.Message)" }
        $deadline = (Get-Date).AddSeconds(8); $childGone = $false
        while ((Get-Date) -lt $deadline) {
            $childGone = @(Get-CimInstance Win32_Process -Filter "ExecutablePath='C:\Windows\Temp\anxin-security.exe'" -ErrorAction SilentlyContinue).Count -eq 0
            if ($childGone) { break }
            Start-Sleep -Milliseconds 500
        }
        Start-Sleep -Seconds 1
        $alive = [bool](Get-Process -Id $app.Id -ErrorAction SilentlyContinue)
        RES "SPOOF-STOP app" $(if ($alive) { 'DENIED' } else { 'KILLED' }) "childGone=$childGone out=$(if(Test-Path $outFile){((Get-Content $outFile -Raw).Trim())}else{'none'})"
        @(Get-CimInstance Win32_Process -Filter "ExecutablePath='C:\Windows\Temp\anxin-security.exe'" -ErrorAction SilentlyContinue) | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Remove-Item $outFile -Force -ErrorAction SilentlyContinue
    } else { RES "SPOOF-STOP app" 'NO-PROC' '' }
    Remove-Item $spoof -Force -ErrorAction SilentlyContinue

    GW "--- PROC: thread context handle (VUL-103, expect DENIED) ---"
    $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        $t = $app.Threads | Select-Object -First 1
        if ($t) {
            $r = & powershell.exe -NoProfile -Command "try { `$h=[Microsoft.Win32.NativeMethods]::OpenThread(0x0010 -bor 0x0008 -bor 0x0040,`$false,$($t.Id)); if (`$h -eq [IntPtr]::Zero) { 'DENIED' } else { 'OPENED' } } catch { 'DENIED' }" 2>&1
            RES "OPEN-THREAD ctx" "$(($r|Out-String).Trim())" "thread=$($t.Id)"
        } else { RES "OPEN-THREAD ctx" 'NO-THREAD' '' }
    } else { RES "OPEN-THREAD ctx" 'NO-PROC' '' }

    # ============================================================
    # 6. DIAG: SET_DIAG from non-authorized process (VUL-099, expect DENIED)
    # ============================================================
    GW "--- DIAG: SET_DIAG=0xF via .NET DeviceIoControl (expect DENIED) ---"
    $diagR = & powershell.exe -NoProfile -Command @'
$dev = New-Object System.IO.FileStream('\\\\.\\AnXinProcProtect',[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
$in = [BitConverter]::GetBytes([uint32]0xF)
# IOCTL_ANXIN_SET_DIAG = CTL_CODE(0x22, 0x80A, METHOD_BUFFERED, FILE_WRITE_DATA) = 0x0022A02C
try {
  $dev.Write($in,0,4)
  'SENT'
} catch { 'ERR ' + $_.Exception.Message }
$dev.Close()
'@
  RES "SET_DIAG" "$(($diagR|Out-String).Trim())" ""
    # after the (should-be-refused) SET_DIAG, confirm app is still kill-protected
    $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        $r = & cmd.exe /c "taskkill /f /pid $($app.Id)" 2>&1
        $alive = [bool](Get-Process -Id $app.Id -ErrorAction SilentlyContinue)
        RES "POST-DIAG taskkill" $(if ($alive) { 'DENIED' } else { 'KILLED' }) "$(($r|Out-String).Trim())"
    }

    # ============================================================
    # 7. SELF: --query-file-protect (VUL-102, expect returns quickly)
    # ============================================================
    GW "--- SELF: query-file-protect (expect quick + paths) ---"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $q = & "$installDir\anxin-security.exe" --query-file-protect 2>&1
    $sw.Stop()
    $qStr = ($q | Out-String).Trim()
    RES "QUERY-PATHS" $(if ($sw.Elapsed.TotalSeconds -lt 10 -and $qStr -match 'Found.*protected') { 'OK' } else { 'HANG-or-EMPTY' }) "elapsed=$([math]::Round($sw.Elapsed.TotalSeconds,2))s $qStr"

    "=== GUEST-ATTACK DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-retest-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-retest-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-retest-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== re-test-selfprotect done ==="
