# antagonist-check-rules-load.ps1 - check which rule file the service actually loads
# by inspecting the service log / process cmdline + rules file timestamps.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== check-rules-load @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
    $out += "--- rule files on disk ---"
    foreach ($p in @('C:\Program Files\AnXinSecurity\config\etw_match_rules.json','C:\Program Files\AnXinSecurity\_up_\config\etw_match_rules.json')) {
        if (Test-Path $p) {
            $i = Get-Item $p
            $raw = [System.IO.File]::ReadAllText($p, (New-Object System.Text.UTF8Encoding($false)))
            try { $n = ($raw | ConvertFrom-Json).Count } catch { $n = '?' }
            $out += "  $p ($($i.Length) B, $n rules, modified $($i.LastWriteTime))"
        } else { $out += "  MISSING: $p" }
    }
    $out += "--- service cwd + cmdline ---"
    $svc = Get-CimInstance Win32_Service -Filter "Name='AnXinSecurityService'" -ErrorAction SilentlyContinue
    if ($svc) { $out += "  PathName=$($svc.PathName)" }
    $out += "--- service process cwd ---"
    $sp = Get-CimInstance Win32_Process -Filter "Name='anxin-security.exe'" -ErrorAction SilentlyContinue
    if ($sp) { $out += "  pid=$($sp.ProcessId) cmd=$($sp.CommandLine)" }
    $out += "--- any engine/rules log ---"
    foreach ($lg in @('C:\Program Files\AnXinSecurity\logs\*.log','C:\Program Files\AnXinSecurity\_up_\logs\*.log','C:\Windows\Temp\anxin*.log','C:\ProgramData\AnXinSecurity\logs\*.log')) {
        Get-ChildItem $lg -ErrorAction SilentlyContinue | ForEach-Object { $out += "  LOG: $($_.FullName) ($($_.Length) B)" }
    }
    $out
}
$r | ForEach-Object { W "  $_" }
Remove-PSSession $s
W "=== check-rules-load done ==="