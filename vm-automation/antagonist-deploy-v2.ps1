# antagonist-deploy-v2.ps1 - deploy full v2 ETW rules (9) + inject headlessAutoTerminate
# via the app's own authorized channel (--write-etw-rules / --set-config as SYSTEM).
param(
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$RulesSrc = 'E:\Project\HTML\AnXinSecurity\vm-automation\output\anxin_etw_rules_v2.json'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Write-Output $m }
"=== deploy-v2 @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

if (-not (Test-Path $RulesSrc)) { W "ERROR: rules source not found: $RulesSrc"; exit 1 }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: connect failed"; exit 1 }
W "PS Direct connected"

# ---- Step 1: copy v2 rules to VM temp ----
$vmTempRules = 'C:\Windows\Temp\anxin_etw_rules_v2.json'
try {
    Copy-Item -Path $RulesSrc -Destination $vmTempRules -ToSession $s -Force
    W "copied v2 rules -> $vmTempRules"
} catch { W "ERROR copy: $($_.Exception.Message)"; Remove-PSSession $s; exit 1 }

# ---- Step 2: deploy via --write-etw-rules as SYSTEM ----
$depOut = Invoke-Command -Session $s -ScriptBlock {
    param($src)
    $out = @()
    $exe = 'C:\Program Files\AnXinSecurity\anxin-security.exe'
    $action = New-ScheduledTaskAction -Execute "$exe" -Argument "--write-etw-rules `"$src`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinDeployV2Rules' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinDeployV2Rules'
    Start-Sleep -Seconds 8
    $ti = Get-ScheduledTaskInfo -TaskName 'AnXinDeployV2Rules' -ErrorAction SilentlyContinue
    if ($ti) { $out += "write-etw-rules: LastTaskResult=$($ti.LastTaskResult)" }
    Unregister-ScheduledTask -TaskName 'AnXinDeployV2Rules' -Confirm:$false -ErrorAction SilentlyContinue
    $rp = 'C:\Program Files\AnXinSecurity\config\etw_match_rules.json'
    if (Test-Path $rp) {
        $raw = [System.IO.File]::ReadAllText($rp, (New-Object System.Text.UTF8Encoding($false)))
        try {
            $n = ($raw | ConvertFrom-Json | Measure-Object).Count
            $out += "rules deployed: $rp ($n rules)"
        } catch { $out += "rules file invalid json: $($_.Exception.Message)" }
    } else { $out += "FAIL: $rp missing" }
    ,$out
} -ArgumentList $vmTempRules
$depOut | ForEach-Object { W "  $_" }

# ---- Step 3: inject headlessAutoTerminate=true via --set-config as SYSTEM ----
$cfgOut = Invoke-Command -Session $s -ScriptBlock {
    $out = @()
    $exe = 'C:\Program Files\AnXinSecurity\anxin-security.exe'
    $action = New-ScheduledTaskAction -Execute "$exe" -Argument "--set-config headlessAutoTerminate=true"
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinSetHeadless' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinSetHeadless'
    Start-Sleep -Seconds 6
    $ti = Get-ScheduledTaskInfo -TaskName 'AnXinSetHeadless' -ErrorAction SilentlyContinue
    if ($ti) { $out += "set-config: LastTaskResult=$($ti.LastTaskResult)" }
    Unregister-ScheduledTask -TaskName 'AnXinSetHeadless' -Confirm:$false -ErrorAction SilentlyContinue
    $cfg = 'C:\Program Files\AnXinSecurity\_up_\config\app.json'
    if (Test-Path $cfg) {
        $o = [System.IO.File]::ReadAllText($cfg, (New-Object System.Text.UTF8Encoding($false))) | ConvertFrom-Json
        $out += "headlessAutoTerminate=$($o.headlessAutoTerminate)"
    } else { $out += "NO app.json at $cfg" }
    ,$out
}
$cfgOut | ForEach-Object { W "  $_" }

# ---- Step 4: restart service to load rules + headless config ----
$rst = Invoke-Command -Session $s -ScriptBlock {
    sc.exe stop AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 4
    sc.exe start AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 6
    $q = sc.exe query AnXinSecurityService 2>&1 | Out-String
    (($q -split "`r?`n") | Where-Object { $_ -match 'STATE' }) -join ''
}
W "SERVICE RESTART: $rst"

Remove-PSSession $s
W "=== deploy-v2 done ==="
