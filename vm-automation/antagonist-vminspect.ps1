# antagonist-vminspect.ps1 - inspect VM state after reinstall: rules, exe features,
# service, driver state. Host-side via PS Direct.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== vminspect @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
    $out += "--- service ---"
    $out += (sc.exe query AnXinSecurityService 2>&1 | Out-String)
    $out += "--- drivers ---"
    foreach ($d in 'AnXinProcProtect','AnXinFileProtect','AnXinProcMon') {
        $q = sc.exe query $d 2>&1 | Out-String
        $st = if ($q -match 'RUNNING') { 'RUNNING' } else { 'NOT-RUNNING' }
        $out += "$d = $st"
    }
    $out += "--- exe ---"
    $exe = Get-Item 'C:\Program Files\AnXinSecurity\anxin-security.exe' -ErrorAction SilentlyContinue
    if ($exe) {
        $out += "bytes=$($exe.Length) modified=$($exe.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        $b = [System.IO.File]::ReadAllBytes($exe.FullName)
        $t = [System.Text.Encoding]::ASCII.GetString($b)
        $out += "supports --set-config = $($t.Contains('set-config'))"
        $out += "contains headlessAutoTerminate = $($t.Contains('headlessAutoTerminate'))"
    } else { $out += "NO EXE" }
    $out += "--- rules (config dir) ---"
    $rp = 'C:\Program Files\AnXinSecurity\config\etw_match_rules.json'
    if (Test-Path $rp) {
        $raw = [System.IO.File]::ReadAllText($rp, (New-Object System.Text.UTF8Encoding($false)))
        try {
            $j = $raw | ConvertFrom-Json
            $out += "count=$($j.Count)"
            $j | ForEach-Object { $out += "  $($_.ruleId) action=$($_.recommendAction)" }
        } catch { $out += "  parse error: $($_.Exception.Message); first 200 chars: $($raw.Substring(0,[Math]::Min(200,$raw.Length)))" }
    } else { $out += "NO rules file at $rp" }
    $out += "--- _up_ rules ---"
    $up = 'C:\Program Files\AnXinSecurity\_up_\config\etw_match_rules.json'
    if (Test-Path $up) {
        $raw = [System.IO.File]::ReadAllText($up, (New-Object System.Text.UTF8Encoding($false)))
        try { $j = $raw | ConvertFrom-Json; $out += "count=$($j.Count)" } catch { $out += "parse error" }
    } else { $out += "NO _up_ rules" }
    $out += "--- app.json headless ---"
    $cfg = 'C:\Program Files\AnXinSecurity\_up_\config\app.json'
    if (Test-Path $cfg) {
        $o = [System.IO.File]::ReadAllText($cfg, (New-Object System.Text.UTF8Encoding($false))) | ConvertFrom-Json
        $out += "headlessAutoTerminate=$($o.headlessAutoTerminate)"
    } else { $out += "NO app.json at $cfg" }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== vminspect done ==="
