# antagonist-diagnose-launch.ps1 - manually copy one sample and launch with
# full error capture to see exactly why it is blocked.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== diagnose-launch @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$manifest = 'E:\Project\HTML\AnXinSecurity\vm-automation\output\sample-retest-leaks.csv'
$all = Import-Csv -Path $manifest
$smpl = $all | Where-Object { [int]$_.Seq -eq 2 }
$src = $smpl.OriginalPath
W "sample: $src"

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }
W "PS Direct connected"

$vmCase = 'C:\Samples\case-2'
$vmFile = "$vmCase\$($smpl.Sha256)$($smpl.Type)"
Invoke-Command -Session $s -ScriptBlock { param($d) New-Item -ItemType Directory -Path $d -Force | Out-Null } -ArgumentList $vmCase
Copy-Item -LiteralPath $src -Destination $vmFile -ToSession $s -Force
W "copied -> $vmFile"

$r = Invoke-Command -Session $s -ScriptBlock {
    param($f)
    $out = @()
    # attempt Start-Process with error capture (no SilentlyContinue)
    try {
        $p = Start-Process -FilePath $f -PassThru -ErrorAction Stop
        $out += "STARTED pid=$($p.Id)"
    } catch {
        $out += "Start-Process ERROR: $($_.Exception.Message)"
        $out += "  Inner: $($_.Exception.InnerException.Message)"
        $hr = [int]$_.Exception.HResult
        $out += "  HRESULT=0x$('{0:X8}' -f $hr)"
    }
    $out += "--- Defender threat detection (last 6) ---"
    try {
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 6 | ForEach-Object {
            $out += "  ThreatID=$($_.ThreatID) Proc=$($_.ProcessName) Res=$($_.Resources)"
        }
    } catch {}
    $out += "--- Defender exclusions ---"
    try { $p = Get-MpPreference; $out += "  Path=$($p.ExclusionPath -join ';') Ext=$($p.ExclusionExtension -join ';')" } catch {}
    $out += "--- check exclusion of the file ---"
    try {
        $mp = (Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe' | Sort-Object FullName -Descending | Select-Object -First 1).FullName
        $out += (& $mp -CheckExclusion -path 'C:\Samples' 2>&1 | Out-String)
    } catch {}
    $out
} -ArgumentList $vmFile
$r | ForEach-Object { W "  $_" }
Remove-PSSession $s
W "=== diagnose-launch done ==="