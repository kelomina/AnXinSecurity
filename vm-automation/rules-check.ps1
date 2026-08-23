# rules-check.ps1 - dump actual ETW rule files inside the VM to confirm which
# ruleset the engine really loads (cwd/exe-dir/_up_ lookup chain) before retest.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-rules-check.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== rules-check @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

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
    $paths = @(
        'C:\Program Files\AnXinSecurity\config\etw_match_rules.json',
        'C:\Program Files\AnXinSecurity\_up_\config\etw_match_rules.json'
    )
    foreach ($p in $paths) {
        $out += "===== $p ====="
        if (-not (Test-Path $p)) { $out += '  MISS'; continue }
        $raw = [System.IO.File]::ReadAllText($p)
        $out += "  bytes=$($raw.Length) first200=$($raw.Substring(0, [Math]::Min(200, $raw.Length)))"
        try {
            $obj = $raw | ConvertFrom-Json
            $arr = @($obj)
            $ids = $arr | ForEach-Object { $_.ruleId }
            $out += "  count=$($arr.Count) ids=$($ids -join ' | ')"
        } catch { $out += "  PARSE FAIL: $($_.Exception.Message)" }
    }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== rules-check done ==="
