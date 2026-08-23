# antagonist-inspect-diag.ps1 - inspect interception diagnostics + sample processes after a run.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== inspect-diag @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }
W "PS Direct connected"

$r = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    $out += "--- sample processes still alive? ---"
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like 'C:\Samples\*' -or $_.CommandLine -like '*C:\Samples\*' }
    if ($procs) { $procs | ForEach-Object { $out += "  pid=$($_.ProcessId) $($_.Name) cmd=$($_.CommandLine)" } } else { $out += "  none" }
    $out += "--- interception diagnostics tail ---"
    $diag = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime\interception_diagnostics.jsonl'
    if (Test-Path $diag) {
        $lines = Get-Content $diag | Select-Object -Last 40
        $out += "  total lines: $((Get-Content $diag | Measure-Object -Line).Lines)"
        $lines | ForEach-Object { $out += "  $_" }
    } else { $out += "  NO diag file" }
    $out += "--- suspended ledger ---"
    $ledger = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime\interception_suspended_processes.json'
    if (Test-Path $ledger) { $out += (Get-Content $ledger -Raw) } else { $out += "  NO ledger" }
    $out += "--- network conns from samples ---"
    $np = @($procs | ForEach-Object { $_.ProcessId })
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $np -contains $_.OwningProcess } | ForEach-Object { $out += "  $($_.RemoteAddress):$($_.RemotePort) pid=$($_.OwningProcess)" }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== inspect-diag done ==="
