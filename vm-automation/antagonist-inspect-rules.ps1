# antagonist-inspect-rules.ps1 - dump the deployed rules file in VM for inspection.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== inspect-rules @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
    $rp = 'C:\Program Files\AnXinSecurity\config\etw_match_rules.json'
    if (Test-Path $rp) {
        $raw = [System.IO.File]::ReadAllText($rp, (New-Object System.Text.UTF8Encoding($false)))
        $out += "file size: $($raw.Length) chars"
        $out += "--- content (first 4000) ---"
        $out += $raw.Substring(0, [Math]::Min(4000, $raw.Length))
    } else { $out += "NO rules file" }
    $out += "--- vm temp v2 source ---"
    $tp = 'C:\Windows\Temp\anxin_etw_rules_v2.json'
    if (Test-Path $tp) {
        $raw = [System.IO.File]::ReadAllText($tp, (New-Object System.Text.UTF8Encoding($false)))
        $out += "temp file size: $($raw.Length) chars"
        try { $out += "temp rules count: $(($raw | ConvertFrom-Json | Measure-Object).Count)" } catch { $out += "temp parse error: $($_.Exception.Message)" }
    } else { $out += "NO temp v2 file" }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== inspect-rules done ==="
