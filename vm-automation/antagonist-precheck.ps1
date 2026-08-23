# antagonist-precheck.ps1 - Phase 0 VM precheck: engine load, ProcMon activity,
# behavior DB baseline, filters, network. Host-side via PS Direct.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-precheck.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== antagonist-precheck @ $(Get-Date -Format HH:mm:ss) ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started" }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VMId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== GUEST-PRECHECK @ $(Get-Date -Format HH:mm:ss) ==="

    "--- services ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinProcMon','AnXinNetFilter','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        $reg = if ($q -match 'does not exist|1060') { 'NOT-REGISTERED' } else { 'registered' }
        "  $svc : $reg $state"
    }

    "--- fltmc filters ---"
    fltmc filters 2>&1 | ForEach-Object { "  $_" }

    "--- engine dir (install) ---"
    $eng = 'C:\Program Files\AnXinSecurity\Engine\Axon'
    if (Test-Path $eng) {
        Get-ChildItem $eng -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object { "  E: $($_.FullName.Replace('C:\Program Files\AnXinSecurity\','')) $($_.Length)B" }
    } else { "  NO ENGINE DIR: $eng" }

    "--- behavior db (systemprofile) ---"
    $bd = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\data\behavior'
    if (Test-Path $bd) {
        Get-ChildItem $bd -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { "  B: $($_.Name) $($_.Length)B mod $($_.LastWriteTime.ToString('MM-dd HH:mm:ss'))" }
    } else { "  NO BEHAVIOR DIR: $bd" }

    "--- interception diagnostics log ---"
    $diag = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime\interception_diagnostics.jsonl'
    if (Test-Path $diag) {
        $n = (Get-Content $diag -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
        "  DIAG LOG: $n lines (last 3)"
        Get-Content $diag -Tail 3 -ErrorAction SilentlyContinue | ForEach-Object { "    $_" }
    } else { "  NO DIAG LOG: $diag" }

    "--- app log tail (engine load evidence) ---"
    Get-ChildItem 'C:\Program Files\AnxInSecurity\logs','C:\Windows\Temp','C:\ProgramData\AnXinSecurity' -Recurse -File -Filter '*.log' -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object { "  L: $($_.FullName) $($_.Length)B" }

    "--- network ---"
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*' } | ForEach-Object { "  IP: $($_.IPAddress) ($($_.InterfaceAlias))" }
    try {
        $t = Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
        "  OUTBOUND-443: $t"
    } catch { "  OUTBOUND-443: error" }

    "--- test user session ---"
    "  whoami: $(whoami)  session: $((Get-Process -Id $PID).SessionId)"

    "=== GUEST-PRECHECK DONE ==="
}
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== antagonist-precheck done ==="
