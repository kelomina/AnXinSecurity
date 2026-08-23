# antagonist-defender-state.ps1 - report Defender realtime state + exclusions.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== defender-state @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
    try {
        $cs = Get-MpComputerStatus
        $out += "RealTimeProtectionEnabled=$($cs.RealTimeProtectionEnabled)"
        $out += "AntivirusEnabled=$($cs.AntivirusEnabled)"
        $out += "TamperProtectionSource=$($cs.TamperProtectionSource)"
    } catch { $out += "status err: $($_.Exception.Message)" }
    try {
        $p = Get-MpPreference
        $out += "DisableRealtimeMonitoring=$($p.DisableRealtimeMonitoring)"
        $out += "ExclusionPath=$($p.ExclusionPath -join ';')"
        $out += "ExclusionProcess=$($p.ExclusionProcess -join ';')"
        $out += "ExclusionExtension=$($p.ExclusionExtension -join ';')"
    } catch { $out += "pref err: $($_.Exception.Message)" }
    $out += "--- threat detections (last) ---"
    try {
        $det = Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 8
        if ($det) { $det | ForEach-Object { $out += "  $($_.ThreatID) $($_.ProcessName) $($_.Resources)" } } else { $out += "  none" }
    } catch { $out += "  threat err: $($_.Exception.Message)" }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== defender-state done ==="
