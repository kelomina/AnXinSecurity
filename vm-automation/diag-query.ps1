# diag-query.ps1 - 查询 minifilter 驱动的实际受保护路径列表。Host-side.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-query.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== diag-query @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

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
    "=== GUEST-QUERY @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $log

    $installDir = 'C:\Program Files\AnXinSecurity'
    GW "--- install-dir files ---"
    Get-ChildItem $installDir -ErrorAction SilentlyContinue | ForEach-Object { GW "  $($_.Name) ($($_.Length) B)" }
    GW "--- resources subdir ---"
    Get-ChildItem (Join-Path $installDir 'resources') -ErrorAction SilentlyContinue | ForEach-Object { GW "  resources\$($_.Name) ($($_.Length) B)" }

    GW "--- app processes ---"
    Get-Process -Name 'anxin-security','hacked' -ErrorAction SilentlyContinue | ForEach-Object { GW "  $($_.Name) pid=$($_.Id) path=$($_.Path)" }

    GW "--- driver state ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect') {
        $q = sc.exe query $svc 2>&1 | Out-String
        GW "  $svc : $((($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join '')"
    }

    GW "--- query protected paths via CLI (renamed binary) ---"
    $exeCandidates = @(
        (Join-Path $installDir 'anxin-security.exe'),
        (Join-Path $installDir 'hacked.exe'),
        (Join-Path $installDir 'hacked2.exe')
    )
    foreach ($exe in $exeCandidates) {
        if (Test-Path $exe) {
            GW "  invoking via cmd: $exe --query-file-protect"
            # GUI-subsystem app: PowerShell '&' detaches without waiting/capturing.
            # cmd.exe DOES wait for GUI apps, so use it to capture CLI output.
            $out = & cmd.exe /c "`"$exe`" --query-file-protect 2>&1"
            $out | ForEach-Object { GW "    $_" }
            break
        }
    }

    GW "--- services app registration: check app log for path registration ---"
    $appLog = "$env:ProgramData\AnXinSecurity\logs"
    if (Test-Path $appLog) {
        Get-ChildItem $appLog -ErrorAction SilentlyContinue | ForEach-Object { GW "  log: $($_.Name) $($_.Length) B" }
        $latest = Get-ChildItem $appLog -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) {
            GW "  --- tail of $($latest.Name) ---"
            Get-Content $latest.FullName -Tail 30 -ErrorAction SilentlyContinue | ForEach-Object { GW "    $_" }
        }
    } else { GW "  no app log dir at $appLog" }

    "=== GUEST-QUERY DONE ===" | Add-Content $log
} -ArgumentList 'C:\Windows\Temp\anxin-diag-query-guest.log'

$out | ForEach-Object { W $_ }
try { Copy-Item -FromSession $s -Path 'C:\Windows\Temp\anxin-diag-query-guest.log' -Destination 'C:\Users\Saika\AppData\Local\Temp\anxin-diag-query-guest.log' -Force -ErrorAction SilentlyContinue } catch {}
Remove-PSSession $s
W "=== diag-query done ==="
