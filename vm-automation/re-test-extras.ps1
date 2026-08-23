# re-test-extras.ps1 - close the gaps from re-test-selfprotect.ps1:
#  1. SET_DIAG via correct DeviceIoControl (VUL-099, expect DENIED for test user)
#  2. webview process kill (VUL-096, expect DENIED once UI fully starts)
#  3. --query-file-protect via cmd (VUL-102, expect quick + paths)
# Host-side.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-retest-extras.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== re-test-extras @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== EXTRAS @ $(Get-Date -Format HH:mm:ss) ==="
    $installDir = 'C:\Program Files\AnXinSecurity'

    # ---- ensure UI running with webview up ----
    $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $app) {
        Start-Process "$installDir\anxin-security.exe" | Out-Null
        $deadline = (Get-Date).AddSeconds(90)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
            $wv = @(Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue)
            if ($wv.Count -gt 0) { break }
        }
        $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if ($app) {
        "app pid=$($app.Id)"
        $wv = @(Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue)
        "webview count after wait: $($wv.Count)"
        foreach ($w in $wv | Select-Object -First 5) { "  wv pid=$($w.Id)" }
        if ($wv.Count -gt 0) {
            $target = $wv[0]
            $r = & cmd.exe /c "taskkill /f /pid $($target.Id)" 2>&1
            $rc = $LASTEXITCODE
            Start-Sleep -Milliseconds 800
            $alive = [bool](Get-Process -Id $target.Id -ErrorAction SilentlyContinue)
            "  [WV-KILL] $(if ($alive) { 'DENIED' } else { 'KILLED' }) :: rc=$rc $(($r|Out-String).Trim())"
        } else { "  [WV-KILL] NO-WEBVIEW" }
    } else { "  app did not start" }

    # ---- SET_DIAG via correct DeviceIoControl (VUL-099) ----
    "--- SET_DIAG=0xF (IOCTL 0x0022A028) from test user (expect DENIED/not-applied) ---"
    $diag = & powershell.exe -NoProfile -Command @'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AnxIo {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] ib, uint il, byte[] ob, uint ol, out uint r, IntPtr ov);
  [DllImport("kernel32.dll")]
  public static extern bool CloseHandle(IntPtr h);
}
"@
$h = [AnxIo]::CreateFile("\\\\.\\AnXinProcProtect", 0xC0000000, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr]::Zero -or $h -eq [IntPtr](-1)) { 'OPEN-FAIL err=' + [Marshal]::GetLastWin32Error(); exit }
$in = [BitConverter]::GetBytes([uint32]0xF)
$out = New-Object byte[] 4
$ret = 0
try {
  $ok = [AnxIo]::DeviceIoControl($h, 0x0022A028, $in, [uint32]$in.Length, $out, [uint32]$out.Length, [ref]$ret, [IntPtr]::Zero)
  if ($ok) { 'SENT-OK (unexpected: DIAG applied?)' } else { 'REFUSED err=' + [Marshal]::GetLastWin32Error() }
} catch { 'ERR ' + $_.Exception.Message }
[AnxIo]::CloseHandle($h) | Out-Null
'@
  $diag | ForEach-Object { "  DIAG: $_" }
    # verify protection still on
    $app = Get-Process -Name 'anxin-security' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($app) {
        $r = & cmd.exe /c "taskkill /f /pid $($app.Id)" 2>&1
        $alive = [bool](Get-Process -Id $app.Id -ErrorAction SilentlyContinue)
        "  [POST-DIAG taskkill] $(if ($alive) { 'DENIED' } else { 'KILLED' }) :: $(($r|Out-String).Trim())"
    }

    # ---- query via cmd (VUL-102) ----
    "--- query-file-protect via cmd ---"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $q = & cmd.exe /c "`"$installDir\anxin-security.exe`" --query-file-protect 2>&1" 2>&1
    $sw.Stop()
    "  elapsed=$([math]::Round($sw.Elapsed.TotalSeconds,2))s rc=$LASTEXITCODE"
    $q | ForEach-Object { "  Q: $_" }
    "=== EXTRAS DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== re-test-extras done ==="
