# antagonist-redeploy-rules.ps1 - on the restored AntagonistReady checkpoint:
# 1) add Defender C:\Samples exclusion  2) deploy full v2 (9) rules via --write-etw-rules
# 3) verify + restart service. Does NOT need --set-config (old exe).
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$RulesSrc = 'E:\Project\HTML\AnXinSecurity\vm-automation\output\anxin_etw_rules_v2.json'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== redeploy-rules @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }
W "PS Direct connected"

# Step 1: add Defender exclusion
$d = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    try { Set-MpPreference -ExclusionPath 'C:\Samples' -ErrorAction SilentlyContinue; $out += "excl set" } catch { $out += "excl err: $($_.Exception.Message)" }
    try { $p = Get-MpPreference; $out += "exclusions now: $($p.ExclusionPath -join ';')" } catch {}
    ,$out
}
$d | ForEach-Object { W "  $_" }

# Step 2: copy v2 rules to VM temp + deploy via --write-etw-rules
$vmTempRules = 'C:\Windows\Temp\anxin_etw_rules_v2.json'
Copy-Item -Path $RulesSrc -Destination $vmTempRules -ToSession $s -Force
W "copied v2 rules -> VM temp"

$r = Invoke-Command -Session $s -ScriptBlock {
    param($src)
    $out = @()
    $exe = 'C:\Program Files\AnXinSecurity\anxin-security.exe'
    # backup current rules
    $rp = 'C:\Program Files\AnXinSecurity\config\etw_match_rules.json'
    if (Test-Path $rp) { Copy-Item -Path $rp -Destination 'C:\Windows\Temp\etw_match_rules_backup.json' -Force; $out += "backup saved" }
    $action = New-ScheduledTaskAction -Execute "$exe" -Argument "--write-etw-rules `"$src`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinDeployRules' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinDeployRules'
    Start-Sleep -Seconds 8
    $ti = Get-ScheduledTaskInfo -TaskName 'AnXinDeployRules' -ErrorAction SilentlyContinue
    if ($ti) { $out += "write-etw-rules LastTaskResult=$($ti.LastTaskResult)" }
    Unregister-ScheduledTask -TaskName 'AnXinDeployRules' -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $rp) {
        $raw = [System.IO.File]::ReadAllText($rp, (New-Object System.Text.UTF8Encoding($false)))
        try { $arr = $raw | ConvertFrom-Json; $out += "rules=$($arr.Count)" } catch { $out += "parse err" }
    } else { $out += "rules file missing" }
    # restart service
    sc.exe stop AnXinSecurityService 2>&1 | Out-Null; Start-Sleep -Seconds 4
    sc.exe start AnXinSecurityService 2>&1 | Out-Null; Start-Sleep -Seconds 6
    $q = sc.exe query AnXinSecurityService 2>&1 | Out-String
    $out += (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
    ,$out
} -ArgumentList $vmTempRules
$r | ForEach-Object { W "  $_" }

Remove-PSSession $s
W "=== redeploy-rules done ==="