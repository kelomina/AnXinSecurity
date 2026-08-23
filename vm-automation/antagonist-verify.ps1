# antagonist-verify.ps1 - verify current VM state before running batch tests.
# Host-side via PS Direct: rules deployment, service/driver status, behavior DB,
# diagnostics/ledger paths, network topology.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-verify.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== antagonist-verify @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started" }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$r = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    $out += "--- services ---"
    foreach ($svc in 'AnXinProcProtect','AnXinFileProtect','AnXinProcMon','AnXinSecurityService') {
        $q = sc.exe query $svc 2>&1 | Out-String
        $state = (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
        $out += "  $svc : $state"
    }
    $out += "--- rule files ---"
    foreach ($p in @(
        'C:\Program Files\AnXinSecurity\config\etw_match_rules.json',
        'C:\Program Files\AnXinSecurity\_up_\config\etw_match_rules.json',
        'C:\Windows\Temp\etw_match_rules_backup.json'
    )) {
        if (Test-Path $p) {
            $sz = (Get-Item $p).Length
            $raw = [System.IO.File]::ReadAllText($p, (New-Object System.Text.UTF8Encoding($false)))
            $n = try { ($raw | ConvertFrom-Json | Measure-Object).Count } catch { 'INVALID' }
            $out += "  EXISTS: $p ($sz B, $n rules)"
        } else { $out += "  MISS  : $p" }
    }
    $out += "--- runtime evidence files ---"
    $rt = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime'
    foreach ($f in 'interception_diagnostics.jsonl','interception_suspended_processes.json') {
        $p = Join-Path $rt $f
        if (Test-Path $p) { $out += "  EXISTS: $p ($((Get-Item $p).Length) B)" } else { $out += "  MISS  : $p" }
    }
    $out += "--- behavior db ---"
    $bd = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\data\behavior\anxin_etw_behavior.db'
    if (Test-Path $bd) { $out += "  EXISTS: $bd ($((Get-Item $bd).Length) B)" } else { $out += "  MISS  : $bd" }
    $out += "--- network ---"
    $out += (Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { "  $($_.Name): $($_.Status) ($($_.InterfaceDescription))" })
    $out += (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { "  IP: $($_.IPAddress) on $($_.InterfaceAlias)" })
    $out
}
$r | ForEach-Object { W $_ }

Remove-PSSession $s
W "=== antagonist-verify done ==="
