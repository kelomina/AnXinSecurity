# antagonist-probe-defender.ps1 - inspect Windows Defender status + behavior DB path in VM.
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-defender-probe.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== defender probe @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

$out = Invoke-Command -Session $s -ScriptBlock {
    "=== isAdmin test-user ==="
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    "isInAdminRole=$($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    "user=$($id.Name)"

    "=== Defender status ==="
    try {
        $cs = Get-MpComputerStatus
        "RealTimeProtectionEnabled=$($cs.RealTimeProtectionEnabled)"
        "AntivirusEnabled=$($cs.AntivirusEnabled)"
        "AntivirusSignatureVersion=$($cs.AntivirusSignatureVersion)"
        "TamperProtectionEnabled=$($cs.IsTamperProtected)"
        "NISEnabled=$($cs.NISEnabled)"
    } catch { "Get-MpComputerStatus error: $($_.Exception.Message)" }
    try {
        $p = Get-MpPreference
        "DisableRealtimeMonitoring=$($p.DisableRealtimeMonitoring)"
        "DisableIOAVProtection=$($p.DisableIOAVProtection)"
        "MAPSReporting=$($p.MAPSReporting)"
        "SubmitSamplesConsent=$($p.SubmitSamplesConsent)"
        "EnableControlledFolderAccess=$($p.EnableControlledFolderAccess)"
    } catch { "Get-MpPreference error: $($_.Exception.Message)" }

    "=== behavior DB paths ==="
    $candidates = @(
        'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\data\behavior\anxin_etw_behavior.db',
        'C:\ProgramData\AnXinSecurity\data\behavior\anxin_etw_behavior.db',
        'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\anxin_etw_behavior.db'
    )
    foreach ($c in $candidates) {
        "exists[$c]=$(Test-Path $c)"
    }
    "--- find db files under AnXinSecurity ---"
    Get-ChildItem -Path 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity' -Recurse -Filter '*.db' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    "--- runtime dir ---"
    Get-ChildItem -Path 'C:\Windows\System32\config\systemprofile\AppData\Roaming\AnXinSecurity\runtime' -ErrorAction SilentlyContinue | Select-Object Name,Length
}
$out | ForEach-Object { W $_; Write-Output $_ }
Remove-PSSession $s
"=== defender probe done ===" | Add-Content $LogPath
