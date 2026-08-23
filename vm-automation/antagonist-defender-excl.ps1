# antagonist-defender-excl.ps1 - try path exclusion + inspect tamper protection registry
$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-defender-excl.log'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== defender excl @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId '7b66415c-52cb-468e-b9bd-368746f42863' -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }

$out = Invoke-Command -Session $s -ScriptBlock {
    "--- try add exclusion C:\Samples ---"
    try { Set-MpPreference -ExclusionPath 'C:\Samples' -ErrorAction Stop; "excl add OK" }
    catch { "excl add ERR: $($_.Exception.Message)" }
    "--- current exclusions ---"
    try { (Get-MpPreference).ExclusionPath -join ';' } catch { "pref err" }
    "--- tamper protection registry ---"
    try {
        $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction SilentlyContinue
        if ($v) { "TamperProtection value=$($v.TamperProtection)" } else { "TamperProtection value NOT FOUND" }
    } catch { "tp read err: $($_.Exception.Message)" }
    try {
        $pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -ErrorAction SilentlyContinue
        if ($pol) { "policy DisableAntiSpyware=$($pol.DisableAntiSpyware)" } else { "policy DisableAntiSpyware not set" }
    } catch { "policy read err" }
    "--- WinDefend service ---"
    (sc.exe qc WinDefend 2>&1 | Out-String)
}
$out | ForEach-Object { W $_; Write-Output $_ }
Remove-PSSession $s
"=== defender excl done ===" | Add-Content $LogPath
