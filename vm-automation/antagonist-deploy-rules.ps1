# antagonist-deploy-rules.ps1 - Deploy a given ETW rules JSON to the VM and
# restart the service so the engine reloads it. Reusable for stage-4 rule
# iteration. Host-side via PS Direct.
#
# FileProtect blocks writes to the install dir from non-SYSTEM processes, so we
# deploy via: anxin-security.exe --write-etw-rules <src>  (schtasks as SYSTEM).
param(
    [Parameter(Mandatory=$true)][string]$RulesFile,
    [string]$VmId = '7b66415c-52cb-468e-b9bd-368746f42863',
    [string]$LogPath = 'C:\Users\Saika\AppData\Local\Temp\anxin-antagonist-deploy.log'
)
$ErrorActionPreference = 'Continue'
function W([string]$m) { Add-Content -Path $LogPath -Value $m; Write-Output $m }
"=== antagonist-deploy-rules @ $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Add-Content $LogPath

if (-not (Test-Path $RulesFile)) { W "ERROR: rules file not found: $RulesFile"; exit 1 }

$vm = Get-VM -Id $VmId -ErrorAction SilentlyContinue
if (-not $vm) { W "ERROR: VM not found"; exit 1 }
if ($vm.State -ne 'Running') { Start-VM -VM $vm; W "VM started" }

$user = 'test'; $pass = 'Kolomina520!'
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$user", (ConvertTo-SecureString $pass -AsPlainText -Force))
$deadline = (Get-Date).AddSeconds(120); $s = $null
while ((Get-Date) -lt $deadline) {
    try { $s = New-PSSession -VmId $VmId -Credential $cred -ErrorAction Stop; break } catch {}
    Start-Sleep -Seconds 2
}
if (-not $s) { W "ERROR: PS Direct connect failed"; exit 1 }
W "PS Direct connected"

# ---- resolve target config path ----
$exeDir = Invoke-Command -Session $s -ScriptBlock {
    $exePath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AnXinSecurityService' -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    if ($exePath -match '"([^"]+)"') { $exePath = $matches[1] }
    [System.IO.Path]::GetDirectoryName($exePath)
}
W "Service exe dir: $exeDir"

# ---- stage rules on VM temp (UTF-8 no BOM) ----
$vmTempRules = "C:\Windows\Temp\anxin_etw_deploy_rules.json"
Copy-Item -Path $RulesFile -Destination $vmTempRules -ToSession $s -Force
W "rules staged in VM: $vmTempRules"

# ---- deploy + restart + verify (SYSTEM) ----
$out = Invoke-Command -Session $s -ScriptBlock {
    param($vmTempRules, $exeDir)
    $exe = "$exeDir\anxin-security.exe"
    $action = New-ScheduledTaskAction -Execute "$exe" -Argument "--write-etw-rules `"$vmTempRules`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Principal $principal
    Register-ScheduledTask -TaskName 'AnXinDeployTestRules' -InputObject $task -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName 'AnXinDeployTestRules'
    Start-Sleep -Seconds 6
    $taskInfo = Get-ScheduledTaskInfo -TaskName 'AnXinDeployTestRules' -ErrorAction SilentlyContinue
    $res = "  CLI LastTaskResult=$($taskInfo.LastTaskResult)"
    Unregister-ScheduledTask -TaskName 'AnXinDeployTestRules' -Confirm:$false -ErrorAction SilentlyContinue

    # restart service to reload rules
    sc.exe stop AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 4
    sc.exe start AnXinSecurityService 2>&1 | Out-Null
    Start-Sleep -Seconds 6
    $q = sc.exe query AnXinSecurityService 2>&1 | Out-String
    $res += "`n  SERVICE: $(($q -split "`r?`n" | Where-Object { $_ -match 'STATE' }) -join '')"

    # verify written file
    $writePath = "$exeDir\config\etw_match_rules.json"
    if (Test-Path $writePath) {
        $raw = [System.IO.File]::ReadAllText($writePath, (New-Object System.Text.UTF8Encoding($false)))
        try {
            $arr = $raw | ConvertFrom-Json
            $res += "`n  DEPLOYED: $writePath  RULES=$($arr.Count)  IDS=$((($arr | ForEach-Object { $_.ruleId }) -join ','))"
        } catch {
            $res += "`n  DEPLOYED-BUT-INVALID-JSON: $($_.Exception.Message)"
        }
    } else {
        $res += "`n  DEPLOY-FAILED: $writePath missing"
    }
    $res
} -ArgumentList $vmTempRules, $exeDir
$out | ForEach-Object { W $_ }
Remove-PSSession $s
W "=== antagonist-deploy-rules done ==="