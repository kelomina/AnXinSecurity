# antagonist-disable-defender.ps1 - disable Windows Defender real-time protection in VM
# so the adversarial test isolates AnXinSecurity's own protection.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-defender-disable.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== defender disable @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    function T([string]$label, [scriptblock]$sb) {
        try { & $sb -ErrorAction Stop; "$label OK" } catch { "$label ERR: $($_.Exception.Message)" }
    }
    T 'DisableRealtimeMonitoring'  { Set-MpPreference -DisableRealtimeMonitoring $true }
    T 'DisableIOAVProtection'      { Set-MpPreference -DisableIOAVProtection $true }
    T 'MAPSReporting'              { Set-MpPreference -MAPSReporting 0 }
    T 'SubmitSamplesConsent'       { Set-MpPreference -SubmitSamplesConsent 2 }
    T 'ControlledFolderAccess'     { Set-MpPreference -EnableControlledFolderAccess Disabled }
    "--- post state ---"
    $p = Get-MpPreference
    "DisableRealtimeMonitoring=$($p.DisableRealtimeMonitoring)"
    "DisableIOAVProtection=$($p.DisableIOAVProtection)"
    "MAPSReporting=$($p.MAPSReporting)"
    "SubmitSamplesConsent=$($p.SubmitSamplesConsent)"
    "EnableControlledFolderAccess=$($p.EnableControlledFolderAccess)"
    "--- defender engine status ---"
    try { $cs = Get-MpComputerStatus; "RealTimeProtectionEnabled=$($cs.RealTimeProtectionEnabled)" } catch { "status err: $($_.Exception.Message)" }
}
$out | ForEach-Object { W $_; Write-Output $_ }
Remove-PSSession $s
"=== defender disable done ===" | Add-Content $LogPath
