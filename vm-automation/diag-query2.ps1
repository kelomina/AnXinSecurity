# diag-query2.ps1 - 恢复 exe 原名后用授权身份查询受保护路径列表。Host-side.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-query2.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-query2 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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
    "=== GUEST-QUERY2 @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    $installDir = 'C:\Program Files\AnXinSecurity'
    GW "--- restore exe name ---"
    $hacked = Join-Path $installDir 'hacked.exe'
    $restored = Join-Path $installDir 'anxin-security.exe'
    if ((Test-Path $hacked) -and -not (Test-Path $restored)) {
        $r = & cmd.exe /c "ren `"$hacked`" anxin-security.exe" 2>&1
        GW "  ren hacked.exe -> anxin-security.exe rc=$LASTEXITCODE $(($r|Out-String).Trim())"
    } else { GW "  restore not needed (hacked=$((Test-Path $hacked)) restored=$((Test-Path $restored)))" }
    Start-Sleep -Milliseconds 500

    GW "--- query protected paths (authorized name) ---"
    if (Test-Path $restored) {
        $out = & cmd.exe /c "`"$restored`" --query-file-protect 2>&1"
        $out | ForEach-Object { GW "    $_" }
    } else { GW "  restored exe missing!" }

    GW "--- also dump FpmQueryPaths result if any via app log? ---"
    GW "--- install dir final state ---"
    Get-ChildItem $installDir -ErrorAction SilentlyContinue | ForEach-Object { GW "  $($_.Name) ($($_.Length) B)" }

    "=== GUEST-QUERY2 DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-query2-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-query2-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-query2-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-query2 done ==="
