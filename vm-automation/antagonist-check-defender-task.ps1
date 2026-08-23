# antagonist-check-defender-task.ps1 - check the defender disable task log.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== check-defender-task @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
    $out += "--- defender2 log ---"
    if (Test-Path 'C:\Windows\Temp\anxin-defender2.log') { $out += Get-Content 'C:\Windows\Temp\anxin-defender2.log' } else { $out += "NO LOG" }
    $out += "--- policies reg ---"
    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    if (Test-Path $p) {
        $v = Get-ItemProperty -Path $p -Name DisableAntiSpyware -ErrorAction SilentlyContinue
        $out += "DisableAntiSpyware=$($v.DisableAntiSpyware)"
        $v2 = Get-ItemProperty -Path $p -Name DisableAntiVirus -ErrorAction SilentlyContinue
        $out += "DisableAntiVirus=$($v2.DisableAntiVirus)"
    } else { $out += "NOT FOUND" }
    $rt = "$p\Real-Time Protection"
    if (Test-Path $rt) {
        $v = Get-ItemProperty -Path $rt -Name DisableRealtimeMonitoring -ErrorAction SilentlyContinue
        $out += "DisableRealtimeMonitoring=$($v.DisableRealtimeMonitoring)"
    } else { $out += "Real-Time Protection NOT FOUND" }
    $out += "--- exclusion policy ---"
    $ep = "$p\Exclusions\Paths"
    if (Test-Path $ep) {
        $v = Get-ItemProperty -Path $ep -Name 'C:\Samples' -ErrorAction SilentlyContinue
        $out += "ExclusionPaths C:\Samples=$($v.'C:\Samples')"
    } else { $out += "ExclusionPaths NOT FOUND" }
    $out
}
$r | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== check-defender-task done ==="