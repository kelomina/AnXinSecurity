# antagonist-sessioncheck.ps1 - check ETW session flags + ProcMon driver state in VM
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863'
)
$ErrorActionPreference = 'Continue'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\test", (ConvertTo-SecureString 'Kolomina520!' -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { Write-Output "ERROR: connect failed"; exit 1 }

$r = Invoke-Command -Session $s -ScriptBlock {
    "--- logman query AnXinETWSession -ets (details) ---"
    $q = logman query AnXinETWSession -ets 2>&1 | Out-String
    $q
    "--- fltmc filters ---"
    fltmc filters 2>&1 | Out-String
    "--- sc query AnXinProcMon ---"
    (sc.exe query AnXinProcMon 2>&1 | Out-String)
    "--- sc query AnXinSecurityService ---"
    (sc.exe query AnXinSecurityService 2>&1 | Out-String)
}
$r
Remove-PSSession $s
