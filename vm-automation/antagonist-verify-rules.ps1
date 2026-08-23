# antagonist-verify-rules.ps1 - verify ETW rules loaded count via service diagnostics.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== verify-rules @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
    # count rules properly: parse array elements
    $rp = 'C:\Program Files\AnXinSecurity\config\etw_match_rules.json'
    if (Test-Path $rp) {
        $raw = [System.IO.File]::ReadAllText($rp, (New-Object System.Text.UTF8Encoding($false)))
        $arr = $raw | ConvertFrom-Json
        $out += "file rules count: $($arr.Count) (array length)"
        $arr | ForEach-Object { $out += "  $($_.ruleId) -> $($_.recommendAction)" }
    }
    # check service log for rule loading evidence
    $out += "--- recent service log files ---"
    Get-ChildItem 'C:\Program Files\AnXinSecurity\logs\*.log','C:\Windows\Temp\anxin*.log','C:\ProgramData\AnXinSecurity\logs\*.log' -ErrorAction SilentlyContinue | ForEach-Object { $out += "  $($_.FullName) ($($_.Length) B)" }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== verify-rules done ==="
