# diag-rename.ps1 - 诊断 VUL-097 rename 绕过范围。在 VM 内通过 PS Direct 运行。
# 目标：判断 install-dir 目录前缀保护对 rename 是普遍失效，还是仅对运行中 exe 失效。
# Host-side script.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-rename.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-rename @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; Start-Sleep -Seconds 15 }

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    param($log)
    function GW([string]$m) { Add-Content -Path $log -Value $m; Write-Output $m }
    function RES([string]$name, [string]$verdict, [string]$detail) { GW "  [$name] $verdict :: $detail" }
    "=== GUEST-DIAG @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    $installDir = 'C:\Program Files\AnXinSecurity'

    GW "--- current install-dir contents ---"
    Get-ChildItem $installDir -ErrorAction SilentlyContinue | ForEach-Object { GW "  $($_.Name) ($($_.Length) B)" }

    # ---- probe: create a new file INSIDE the protected install dir ----
    $probe = Join-Path $installDir 'probe_rename.txt'
    Set-Content -Path $probe -Value 'probe' -ErrorAction SilentlyContinue
    GW "PROBE-CREATED: $(Test-Path $probe)"

    # ---- 1. delete probe (expect DENIED via dir prefix) ----
    $before = Test-Path $probe
    & cmd.exe /c "del /f /q `"$probe`"" 2>&1 | Out-Null
    Start-Sleep -Milliseconds 300
    $after = Test-Path $probe
    RES "DEL probe (install dir)" $(if ($before -and $after) { 'DENIED' } elseif ($before -and -not $after) { 'DELETED' } else { 'NO-FILE' }) ''

    # recreate if deleted
    if (-not (Test-Path $probe)) { Set-Content -Path $probe -Value 'probe' -ErrorAction SilentlyContinue }

    # ---- 2. rename probe (expect DENIED via dir prefix) ----
    $renTo = Join-Path $installDir 'probe_renamed.txt'
    Remove-Item $renTo -Force -ErrorAction SilentlyContinue
    $before = Test-Path $probe
    $r = & cmd.exe /c "ren `"$probe`" probe_renamed.txt" 2>&1
    $rc = $LASTEXITCODE
    Start-Sleep -Milliseconds 300
    $after = Test-Path $probe
    $renamed = Test-Path $renTo
    RES "RENAME probe (install dir)" $(if ($before -and $after -and -not $renamed) { 'DENIED' } elseif ($renamed) { 'RENAMED' } else { 'OTHER' }) "rc=$rc renTo=$renamed $(($r|Out-String).Trim())"

    # ---- 3. rename probe -> OUTSIDE install dir ----
    $outside = 'C:\Windows\Temp\probe_renamed.txt'
    Remove-Item $outside -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $probe)) { Set-Content -Path $probe -Value 'probe' -ErrorAction SilentlyContinue }
    $before = Test-Path $probe
    $r = & cmd.exe /c "ren `"$probe`" `"C:\Windows\Temp\probe_renamed.txt`"" 2>&1
    $rc = $LASTEXITCODE
    Start-Sleep -Milliseconds 300
    $movedOut = Test-Path $outside
    RES "RENAME probe -> outside" $(if ($before -and -not $movedOut) { 'DENIED' } elseif ($movedOut) { 'RENAMED-OUT' } else { 'OTHER' }) "rc=$rc movedOut=$movedOut $(($r|Out-String).Trim())"

    # ---- 4. overwrite probe (expect DENIED) ----
    if (-not (Test-Path $probe)) { Set-Content -Path $probe -Value 'probe' -ErrorAction SilentlyContinue }
    $szBefore = (Get-Item $probe -ErrorAction SilentlyContinue).Length
    & cmd.exe /c "echo evil > `"$probe`"" 2>&1 | Out-Null
    Start-Sleep -Milliseconds 300
    $szAfter = (Get-Item $probe -ErrorAction SilentlyContinue).Length
    RES "OVERWRITE probe" $(if ($szAfter -eq $szBefore) { 'DENIED' } else { 'MODIFIED' }) "before=$szBefore after=$szAfter"

    # ---- 5. rename the (running) exe - note if it still exists ----
    GW "--- running exe rename probe ---"
    $exe = Join-Path $installDir 'anxin-security.exe'
    if (Test-Path $exe) {
        $r = & cmd.exe /c "ren `"$exe`" hacked2.exe" 2>&1
        $rc = $LASTEXITCODE
        $renamed2 = Test-Path (Join-Path $installDir 'hacked2.exe')
        RES "RENAME exe (if exists)" $(if ($renamed2) { 'RENAMED' } elseif (Test-Path $exe) { 'DENIED' } else { 'NO-FILE' }) "rc=$rc $(($r|Out-String).Trim())"
    } else { GW "  exe already gone (renamed by previous test)" }

    # ---- 6. rename a driver .sys (expect DENIED - driver self-protect) ----
    $drv = 'C:\Windows\System32\drivers\AnXinFileProtect.sys'
    if (Test-Path $drv) {
        $r = & cmd.exe /c "ren `"$drv`" hacked.sys" 2>&1
        $rc = $LASTEXITCODE
        RES "RENAME driver .sys" $(if (Test-Path $drv) { 'DENIED' } else { 'RENAMED' }) "rc=$rc $(($r|Out-String).Trim())"
    } else { GW "  driver .sys missing" }

    "=== GUEST-DIAG DONE @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-rename-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-rename-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-rename-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-rename done ==="
